# HTTP gateway

`hellas gateway` builds one daemon document from repeatable flags and runs in
the foreground. It saves no routing configuration. Local models, friends'
grants and API upstreams can appear together:

```sh
hellas gateway \
  --model hf://ggml-org/Qwen3-0.6B-GGUF@afe8ad3577aa22500b3cd1c880f153b3b0e1cae8/Qwen3-0.6B-BF16.gguf \
  --model hf://unsloth/whisper-tiny@34457cb234c8624f23ac716000773b367000df6e \
  --model hf://black-forest-labs/FLUX.2-klein-4B@e7b7dc27f91deacad38e78976d1f2b499d76a294 \
  --model hf://ggml-org/Qwen3-0.6B-GGUF@afe8ad3577aa22500b3cd1c880f153b3b0e1cae8/Qwen3-0.6B-BF16.gguf@alice \
  --upstream openrouter=https://openrouter.ai/api,key-file="$HOME/or.key" \
  --model gpt-5@openrouter
```

The gateway serves local or pinned GGUF text and decision models, original
Whisper, MMS, OmniVoice, Flux and Phonon checkpoints. It discovers the modality and API paths from the model.
Append `@CONTACT` to a model path or pinned URI to use a remote Compute grant. A Fetch
grant uses `NAME@CONTACT`, checked against the models in its signed offer.
Import contacts and access with `hellas pair … --name CONTACT`. For an App
Attest provider, independently approve its pins under the same contact name:
`hellas trust --store "$HELLAS_HOME/trust" approve CONTACT --policy POLICY.json
--expected-revision 0 --reason REASON` (use `~/.hellas/trust` for the default
home). The bundle cannot approve or replace those pins.

## Model sources

For a GGUF, give the gateway a pinned Hub reference. Append the contact name to run on a grant provider:

```sh
hellas gateway --model hf://LiquidAI/LFM3-1.7B-GGUF@cd0c74c575b5c416f3011b5b4c298077f26ca8c2/LFM3-1.7B-BF16.gguf@alice
```

The gateway reads the GGUF header for the tokenizer, template and tensor ranges. The provider acquires and verifies the weight file. Local GGUF paths also work.

Whisper clients read the tokenizer, generation settings and safetensors header. The provider verifies the original weight file and prepares the selected tensors on its GPU. You can also select a local directory containing the original checkpoint files.

```sh
hellas gateway --model hf://unsloth/whisper-tiny@34457cb234c8624f23ac716000773b367000df6e@alice
hellas program hf://MisterCD/whisper-small@98533e05a8a8d670fa562f13392b78841424f44f --backend hellas/catena-dfad87438018-cuda
```

For MMS English and other speech checkpoints, see [speech](speech.md).

## Upstreams and HTTP access

`NAME@UPSTREAM` selects a named OpenAI-compatible HTTPS endpoint. Its key file
is read once and the key remains write-only in the configuration. Startup
prints a table of model, modality, API path, backend, state and jobs in flight.
The same model selection is available in a TOML service configuration; there
are no per-modality flags.

The default HTTP address is `127.0.0.1:8080`; `--bind ADDRESS:PORT` changes it.
Every request requires a scoped `gateway.invoke` bearer. The foreground
command prints its bearer to the terminal, or passes it directly to a child:

```sh
hellas gateway --model hf://ggml-org/Qwen3-0.6B-GGUF@afe8ad3577aa22500b3cd1c880f153b3b0e1cae8/Qwen3-0.6B-BF16.gguf --wrap claude
```

`--wrap` supplies OpenAI and Anthropic URLs and tokens, and drains accepted
work when the child exits. For headless clients, use `--bearer-file PATH`:

```sh
hellas gateway --model hf://ggml-org/Qwen3-0.6B-GGUF@afe8ad3577aa22500b3cd1c880f153b3b0e1cae8/Qwen3-0.6B-BF16.gguf --bearer-file "$HOME/gateway.bearer"
# In another shell:
curl -H "Authorization: Bearer $(cat "$HOME/gateway.bearer")" \
  -H "Content-Type: application/json" \
  -d '{"model":"Qwen3-0.6B-BF16","messages":[{"role":"user","content":"Hello"}]}' \
  http://127.0.0.1:8080/v1/chat/completions
```

The parent directory must exist. The file is replaced atomically with mode
0600 on each start. Without a wrapper, bearer file or controlling terminal,
startup fails. The NixOS gateway unit writes `/run/hellas-gateway/bearer` inside
its private runtime directory; an administrator can read it for an authorized
client. The bearer changes on restart.

## Shared TOML configuration

For repeatable startup, both forms accept `--config PATH`:

```toml
models = ["/srv/models/qwen3.gguf", "hf://unsloth/whisper-tiny@34457cb234c8624f23ac716000773b367000df6e", "gpt-5@api"]

[upstreams.api]
url = "https://api.example.com/v1"
key_file = "/run/secrets/api.key"

[listeners.api]
kind = "http"
bind = "127.0.0.1:8080"
zdr = true # default; set false explicitly to retain request/response data
```

```sh
hellas gateway --config gateway.toml --wrap claude
```

`gateway --config` requires exactly one HTTP listener (its name is arbitrary). It rejects
paid provider terms and cannot be mixed with `--model`, `--upstream` or `--bind`.
The existing flags remain useful for foreground use and compile into the same
daemon document. The gateway retains its ephemeral HTTP authority and bearer
behavior; it does not journal routing configuration.

The TOML schema is the SDK's daemon document (`listeners`, `backends`, `routes`,
`resources`, `machine`, `budgets`, `limits`, `execution`), plus `models`,
`upstreams` and optional `paid_policy`. Models and upstreams are resolved into
that document with the same logic as route/backend edits. Use a pinned Hub URI or a local model path. Multiple local model routes share a serialized executor for each
evaluator, rather than running GPU jobs concurrently.

`execution.queue_capacity`, `execution.session_programs` and
`execution.session_asset_bytes` bound the local executor. Queue capacity may be
zero (no waiting jobs); cache counts/bytes must be positive. Absent values use
native defaults. Changing them requires a daemon restart.
For a provider add an iroh listener, for example:

```toml
[listeners.work]
kind = "iroh"
port = 31145
backends = ["local"]
```

`hellas --passkey /run/secrets/owner.passkey serve --config provider.toml`
approves a fresh local authority without a pairing prompt, then reconciles the
complete document before listening. The software passkey, saved approval and
initial credential remain runtime data. Identical restarts retain revisions;
changes and removals are journaled while identity, payment state, usage and
outstanding duties survive. `--config` conflicts with `serve --port`; declare
the listener port in TOML. Existing paired authorities without a local startup
credential are refused rather than replaced. See [Nix deployments](nix.md) for
paid terms, runtime paths and retained control-profile details.

## Persistent service

`hellas serve` runs the same core, restoring its document from the authority
journal. An explicit `serve --port PORT` changes the saved iroh port through
a journaled configuration edit before listening; later starts without the flag
restore that port. A fresh node has no HTTP listener. Pair its printed invite first, then use the
paired profile for edits:

```sh
hellas backend add upstream https://api.example.com/v1 --key-file "$HOME/api.key"
hellas route add gpt-5@upstream
hellas route add hf://ggml-org/Qwen3-0.6B-GGUF@afe8ad3577aa22500b3cd1c880f153b3b0e1cae8/Qwen3-0.6B-BF16.gguf
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

A missing model or failed backend activation appears as Down with its error;
the control service remains available to repair the document. A failure after
the journal commit returns an error naming the committed revision and is also
visible on Watch. Paid backends contact their provider on the first request.
An unreachable provider marks that backend Down; other routes remain usable.

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

HTTP listeners default to ZDR: request and response payloads are not archived.
This governs application writes, not OS swap, upstream retention or client logs.
Setting `zdr = false` enables archives under `<home>/gateway-archive`, excluding
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

Generic HTTP Fetch admits up to 8 MiB of raw response bytes. Its default policy
sizes event JSON, artifact framing, signed envelopes and retained memory
separately; the raw allowance is not the transcript spool allowance. The signed
policy also bounds the number of response events, so a stream fragmented into
too many tiny deliveries can exhaust that allowance before reaching 8 MiB.
A response whose Content-Length already exceeds the signed raw bound is refused
before forwarding its head. With an unknown length, bytes within the bound can
already have streamed: exceeding it terminates the signed job with `CallerLimit`
and leaves the HTTP body incomplete. Failed jobs are not credited as completed
responses.

## Telemetry

An `otel` build enables `--metrics-port` and `--metrics-addr` for Prometheus.
The metrics endpoint is unauthenticated and binds to loopback by default.
`hellas routes` reads current backend health and jobs from `Watch`. Trace
attributes name configured backends and models; they exclude payloads,
credentials and raw session identifiers.

Speech uses the same gateway routes and backends: see [hosted and MMS speech](speech.md).
