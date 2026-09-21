# Paid inference gateway

`hellas-cli gateway --paid-work-config /srv/hellas/pool.json` sends token-native
inference to the configured providers and pays through their real funded work
channels. Each provider has its own endpoint identity, bond, payment funding,
and client journals. The gateway prefers idle matching providers and matching
prompt prefixes, then serializes requests within each channel.

The pool file uses the provider's existing `--work-config` policy and chain
configuration:

```json
{
  "providers": [
    {
      "work_config": "/srv/hellas/provider-a-work.json",
      "journal_root": "/var/lib/hellas-gateway/provider-a",
      "provider": "PROVIDER_ENDPOINT_ID",
      "provider_addrs": ["192.0.2.10:31145"],
      "bond": "PROVIDER_BOND_EDGE_HEX",
      "payment_coins": ["CLIENT_PAYMENT_COIN_HEX"],
      "omission_bond": 10
    }
  ],
  "acceptance_blocks": 16,
  "terminal_blocks": 64,
  "payment_blocks": 32,
  "timeout_secs": 300,
  "max_pending_requests": 64
}
```

Provision provider bonds with `hellas-cli provision`; coin
values and policy terms must agree with the provider work config. Payment coins
must be owned by the gateway settlement identity and cannot fund two channels.
The provider's route table must authorize the gateway transport and settlement
identities. All participants must use the same compatible chain revision.

Pass the environment, tokenizer, model label, `--default-max-tokens`, and
`--stop-token` options as for an ordinary gateway. A paid execution policy fixes
the environment, maximum output tokens, stop IDs, and price per job. Requests
may request a shorter output within the configured ceiling. Model presentation
lives in the shared `hellas-presentation` adapter, usable by clients and the
gateway. Select `--chat-template qwen3` for chat messages and function tools;
the adapter binds the input template and output parser to the same offered tools.
Catena execution receives committed tokens and generation settings.

The provider reserves delivery credit before streaming signed token prefixes.
The gateway verifies each prefix as it arrives, then authenticates and journals
the complete result and obtains the provider's durable payment acknowledgement
before reporting completion. One open subscription replaces repeated result
polls. Payment is an accumulating channel certificate. Channels stay open and
follow finalized blocks while idle; they settle through the existing close
protocol. The pool does not automatically refill exhausted channels.

The shared `--output-cache record` mode also covers paid inference. Repeating
an identical recorded request reuses its output without another paid job. A
recording becomes replayable only after successful completion and payment
acknowledgement; `--output-cache replay-only` reads it without connecting to
providers or validators.

Keep gateway and provider identities and journals across service restarts,
including when the operating system's store is ephemeral. Startup recovers
unfinished jobs and re-sends retained payments idempotently. Disconnecting an
HTTP client cancels work that has not yet been proposed. Once a signed proposal
may have reached a provider, collection and payment continue despite disconnects.
The pool admits at most `max_pending_requests` queued or running requests (default
64); additional requests receive HTTP 503 and may be retried. `timeout_secs`
bounds queueing, recovery, provider fallback, execution and payment together,
rather than restarting for each provider. Interactive requests skip busy provider
channels; each connection attempt gets at most 10 seconds before trying another
route within that shared budget. The HTTP paid route uses this same
configured budget; non-paid routes retain their existing 3600-second default. HTTP delivery has an
8 MiB byte budget (including event overhead), allowing retained-result bursts.
A consumer that exhausts it receives a stream error; its accepted work continues
settlement without waiting for HTTP backpressure.

SIGTERM and wrapped-command failures drain outstanding operations. Set the service
stop timeout above `timeout_secs`. An operation that reaches its deadline retains
its journal for recovery, as does abrupt process termination.

For systemd, set `--bearer-token-file /var/lib/hellas-gateway/bearer-token`.
The file is created with mode 0600 and reused across restarts. Clients read its
trimmed contents as `Authorization: Bearer <credential>`. The configured listener
may bind an explicitly selected LAN address; the default stays `127.0.0.1`.
Every route still requires bearer authentication. Use a trusted local network or
a TLS reverse proxy when configuring remote access.

The NixOS options are `services.hellas.gateway.paidWorkConfig`,
`paidWorkJournalRoots` (the writable client journal directories), and
`bearerTokenFile`, alongside the existing environment and tokenizer options.

## Request traces

Build with the opt-in `otel` feature and set `OTEL_EXPORTER_OTLP_ENDPOINT`
to the collector's HTTP base URL on clients, gateways, providers and validators.
The SDK appends `/v1/traces` and `/v1/metrics`; signal-specific endpoint variables
accept complete URLs instead. Give these services distinct `OTEL_SERVICE_NAME`
values. Validators require both `validator` and `otel`. Sampling honors the
upstream sampled flag; `OTEL_TRACES_SAMPLER=parentbased_traceidratio` with
`OTEL_TRACES_SAMPLER_ARG` controls new root traces. Default packages omit the
telemetry SDK and exporters; Nix module `otel` options select enabled builds.

The gateway accepts W3C `traceparent`/`tracestate` headers and returns
`traceparent` plus `x-hellas-trace-id` for trace lookup. Without an incoming
context it starts a new trace. HTTP spans remain alive while SSE is being
consumed; paid tasks retain their parent after an HTTP disconnect. Generic
Hellas RPC metadata carries the context over both Iroh and WebSocket mux
connections, including validator queries and submissions. Transparent frame
relays preserve this metadata. The explorer relay continues the context through
its forwarding span, and proof-origin HTTP queries continue the caller trace.
Background indexer polling is independent of the paid request trace.

Useful spans include `http.server`, `paid.gateway`, `paid.queue`,
`paid.executor.stream`, GenAI `chat MODEL` and `text_completion` operations,
and RPC spans named for their full service/method. RPC method and status are
attributes. GPU spans report queue wait, first-token latency, cache reuse and
input/output token counts; HTTP spans report first body delivery, status, byte
count and completion. Spans do not contain prompts, token values, authorization
headers or tool data. Log events stay in the log sink and are excluded from
the OTLP span exporter.

An instrumented HTTP client should inject its active context on every request.
For a manual correlation check, send a fresh valid W3C `traceparent` header and
look up its 32-character trace ID in Jaeger. Reusing one fixed header across
unrelated requests combines those requests into one trace and should be avoided.

### End-to-end check traces

The VM checks under `hydraJobs.x86_64-linux.e2e` use telemetry-enabled test
packages and a local collector. Each check publishes
`traces/<machine>/traces.jsonl` as a Hydra build product, with collector
diagnostics alongside it. The files contain newline-delimited
[OTLP JSON exports](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/fileexporter)
and can be imported through the collector's `otlpjsonfile` receiver.
They capture the requests made by the existing provider, gateway and chain
checks; test data stays inside the test VMs and their check outputs.

Hydra retains these outputs on test failure using its `nix-support/failed`
convention, so a failing check still has downloadable traces. Local
`nix build .#nixosTests.x86_64-linux.<name>` keeps the usual failing exit status;
use the Hydra attribute when retaining failure outputs is needed. Public
packages still build without telemetry by default.

## Prefill and prefix reuse

Environments can commit a fixed generation capacity and prefill chunk size.
These parameters are observable by arbitrary Catena programs, so adopting them
creates a new environment identity. Legacy environments retain their original
whole-prompt evaluation. The Qwen example uses capacity 32768 and chunks of 64
tokens to bound cumulative temporary allocations at long contexts.

To apply this schedule to already verified metadata without rehashing weights:

```sh
hellas-cli environment schedule --environment model.environment \
  --fixed-capacity 32768 --prefill-chunk-tokens 64 \
  --out model.interactive.environment
```

Update gateway and provider policies to the new manifest identity. The provider
must admit the fixed capacity even for short requests. Hellas retains at most
one prefix checkpoint per GPU worker, capped at 8 GiB and charged to the
generation's device-memory envelope. Qwen's checkpoint at this capacity is
6 GiB, alongside 6 GiB of active state. Requests reuse only an exact token
prefix at the same model, capacity, and chunk boundary; every mutable state
buffer is copied independently. A changed prefix or insufficient cache budget
starts cold. `gpu.generate` records `hellas.reused_prompt_tokens` and
`hellas.prefill_steps` without recording token values.
