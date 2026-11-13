# HTTP gateway

`hellas gateway` builds one daemon document from repeatable flags and runs in
the foreground. It saves no routing configuration. Local models, friends'
grants and API upstreams can appear together:

```sh
hellas gateway \
  --model ./qwen3.gguf --model ./whisper-tiny --model ./flux \
  --model ./qwen3.gguf@alice \
  --upstream openrouter=https://openrouter.ai/api,key-file="$HOME/or.key" \
  --model gpt-5@openrouter
```

A local path accepts the existing `ModelPackage` formats: Qwen GGUF and
converted Whisper or Flux directories. The package determines the modality
and API paths. Remote Compute uses `PATH@CONTACT`: the gateway needs that
local package to render the invocation for the contact's evaluator. A Fetch
grant uses `NAME@CONTACT`, checked against the models in its signed offer.
Import contacts and access with `hellas pair … --name CONTACT`. For an App
Attest provider, independently approve its pins under the same contact name:
`hellas trust --store "$HELLAS_HOME/trust" approve CONTACT --policy POLICY.json
--expected-revision 0 --reason REASON` (use `~/.hellas/trust` for the default
home). The bundle cannot approve or replace those pins.

`NAME@UPSTREAM` selects a named OpenAI-compatible HTTPS endpoint. Its key file
is read once and the key remains write-only in the configuration. Startup
prints a table of model, modality, API path, backend, state and jobs in flight.
There are no routing files or per-modality flags.

The default HTTP address is `127.0.0.1:8080`; `--bind ADDRESS:PORT` changes it.
Every request requires a scoped `gateway.invoke` bearer. The foreground
command prints its bearer to the terminal, or passes it directly to a child:

```sh
hellas gateway --model ./qwen3.gguf --wrap claude
```

`--wrap` supplies OpenAI and Anthropic URLs and tokens, and drains accepted
work when the child exits. For headless clients, use `--bearer-file PATH`:

```sh
hellas gateway --model ./qwen3.gguf --bearer-file "$HOME/gateway.bearer"
# In another shell:
curl -H "Authorization: Bearer $(cat "$HOME/gateway.bearer")" \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen3","messages":[{"role":"user","content":"Hello"}]}' \
  http://127.0.0.1:8080/v1/chat/completions
```

The parent directory must exist. The file is replaced atomically with mode
0600 on each start. Without a wrapper, bearer file or controlling terminal,
startup fails. The NixOS gateway unit writes `/run/hellas-gateway/bearer` inside
its private runtime directory; an administrator can read it for an authorized
client. The bearer changes on restart.

## Persistent service

`hellas serve` runs the same core, restoring its document from the authority
journal. An explicit `serve --port PORT` changes the saved iroh port through
a journaled configuration edit before listening; later starts without the flag
restore that port. A fresh node has no HTTP listener. Pair its printed invite first, then use the
paired profile for edits:

```sh
hellas backend add upstream https://api.example.com/v1 --key-file "$HOME/api.key"
hellas route add gpt-5@upstream
hellas route add /srv/models/qwen3.gguf
hellas route listen 127.0.0.1:8081
hellas routes
hellas route rm gpt-5@upstream
hellas backend rm upstream
```

Each mutation reads `Watch`, changes the complete document and sends one
`Configure` with its expected revision. A stale revision or invalid candidate
changes nothing. The authority journal commits the document, resources and
budgets in one frame; the serving snapshot changes only after durability.
Commit and publication survive the control caller disconnecting. `Watch`
reports the result to other callers. Keys are never echoed.

Local package paths must be readable at the same path by the editing CLI and
the daemon. A removed backend stays alive for admitted work. Resource edits
keep accepted terms by default; a resource's `release` option instead cancels
its existing work. Revocation, expiry and quarantine always stop work.

The stateful HTTP listener uses explicitly issued HTTP credentials from the
node authority; a control credential is not an HTTP bearer. Embedders use
`Configure`, `Watch` and `CancelJob` for the same operations.

## Routing and sessions

Repeating a model for several backends preserves their order. Selection skips
unavailable or full candidates before a proposal. After a proposal, the job
belongs to that backend: errors and connection loss never replay it elsewhere.
Several jobs can run on the same Grant or Paid backend within its capacity.
An iroh listener makes one exact lookup by Compute evaluator or Fetch service
and method, and can serve only local and Fetch backends.

Affinity recognizes `x-hellas-session-id`, Claude Code's
`x-claude-code-session-id`, Codex's `session-id`/`thread-id`, Claude's session ID
in `metadata.user_id`, and `prompt_cache_key` (used by Kimi Code), in that order.
An explicit session survives changes of client connection. Without one, requests
for the same model/API on the same accepted HTTP connection stay together.
Connection-only bindings are reclaimed once that connection closes. Different
explicit sessions may share that connection. Affinity is scoped by
model and API family; Responses compaction and Messages token counting share
their generation API's family. Unchanged backends keep their instance across
configuration edits. Replacing or removing a pinned backend drops session and
connection affinity so a full-context request can select again.

Responses API IDs observed in JSON or SSE bind `previous_response_id` and
`conversation` continuations to the original backend, including continuations
that omit the model. Unknown, expired or
conflicting state returns 409 before contacting an upstream. A continuation tied
to a replaced backend returns 409 and its binding is discarded; resend full
context without that continuation to establish fresh affinity. Session identifiers
are held as salted hashes in a bounded memory table (16,384 entries, 24 hours
idle). Unexpired entries are not evicted to admit new sessions; a full table
returns 503. Restarting the gateway clears affinity. Server-side continuations
whose mapping was lost require full context rather than being sent to a guessed
account. Full-history requests can establish new affinity after a restart.

Model routing reads JSON, gzip or zstd requests with an 8 MiB decoded limit and
an 8 MiB zstd window limit. It forwards the original encoded bytes. An unsupported
model receives 404; malformed or unsupported routing input receives 400. These
checks precede upstream execution. Model-less, empty-body auxiliary requests use
an eligible backend; account-specific quota endpoints are not aggregated.

## Payloads and cancellation

The CLI's HTTP listeners use ZDR: request and response payloads are not
archived. This governs application writes, not OS swap, upstream retention or
a coding client's session logs. Embedders can configure an HTTP listener's
archive policy; archives then live under `<home>/gateway-archive` and exclude
authentication headers. A request can further restrict persistence with
`x-hellas-zdr: true`.

Before proposal, disconnect or `CancelJob` prevents execution. After a remote
proposal, cancellation stops delivery while collection and settlement remain
owned by the daemon. Shutdown drains these obligations. Fetch payloads held
only in memory cannot be reconstructed after restart; retained signatures and
payment evidence still support recovery without replaying the request.

Upstream HTTP status and allowed end-to-end headers reach the caller. Cookies,
hop-by-hop headers and gateway credentials are removed. Responses obey the
signed Fetch envelope and transcript limits as well as the granted or paid
policy. Bodies that exceed those limits fail as incomplete rather than being
silently truncated into a successful result.

## Telemetry

An `otel` build enables `--metrics-port` and `--metrics-addr` for Prometheus.
The metrics endpoint is unauthenticated and binds to loopback by default.
`hellas routes` reads current backend health and jobs from `Watch`. Trace
attributes name configured backends and models; they exclude payloads,
credentials and raw session identifiers.
