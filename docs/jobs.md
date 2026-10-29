# Paid jobs

`hellas transact --job DIR` executes a caller-owned job folder for any
application. `hellas run` (one call of a Catena program) and `hellas fetch`
(one HTTPS request) build such a folder and go through the same SDK
transaction. Requesters run no node: they keep local signing keys and
wallet/channel metadata, and chain reads use authenticated validator RPCs.

```sh
hellas --faucet run --provider ENROLLMENT_ID@NODE_ID --source counter.hex --entry advance \
  --arg u64:2 --arg u64:3 --returns u64 --payment 20 --save-job ./add
hellas --faucet transact --job ./add --provider ENROLLMENT_ID@NODE_ID@127.0.0.1:9000 -o ./result
hellas --faucet fetch https://example.com/data --provider ENROLLMENT_ID@NODE_ID --payment 20 \
  --contract http --spki-sha256 LEAF_SPKI_SHA256 --save-job ./request -o ./response
hellas --faucet transact --settle --provider ENROLLMENT_ID@NODE_ID
```

`--provider` takes the address `hellas serve` prints: the content ID of the
provider's enrollment bundle and the node ID it binds, optionally followed by
`@IP:PORT`. Quotes, funding, payment and every reconnect refuse a provider that
presents any other enrollment, before anything is signed or funded.

`--faucet` only selects a key from the devnet genesis faucet allocation and
retains it beside the identity; `--faucet-account N` selects one explicitly,
and `--passkey FILE` uses your own owner key. Faucet keys are public
development keys. The default chain is the shipped devnet. A custom chain uses `--trust FILE`, `--genesis FILE`, and six
repeated `--validator URL` options. `--timeout 90s` bounds the whole operation;
without it the command waits until the job is done. `--state-dir DIR` selects
requester state.

The authenticated quote must admit the application's exact manifest and price.
Those checks and the advertised input limits run before new channel funding.
Fetch's encoded-input size check uses the largest purchase-nonce encoding,
reserving up to 32 bytes more than a particular purchase needs. One owner
approval funds the quoted channel amount; later jobs reuse its balance.
`--settle` closes the channel after the job. With no `--job`, it closes
retained channels without requesting new funding.

## Results

Before paying, the requester checks that the result is signed by the provider
and matches this job: every declared output has its declared kind and bound,
and a step loop stopped by its stop rule. The command prints `signed by provider
… and matches this job …`. Hellas does not re-run the job, so the signature
shows who answered, not that the answer is correct.

`run` and `transact` print the decoded outputs; `-o DIR` instead writes the
signed transcript (`transcript.cbor`), result identifiers (`result.json`),
`output.json` and one `output-NNNN` file per output. `fetch -o FILE` writes the
raw HTTPS response body; without `-o` it writes that body to stdout and its
payment report to stderr.

## Compute jobs

`run` compiles nothing locally. It puts the `--source` files (in order) into
the job and makes one call of `--entry`. `--arg` gives the call arguments in
order: `bool:B`, `u16:N`, `u32:N`, `u64:N`, `f32:X`, `zeroed:BYTES` (a zeroed
buffer) or `input:NAME`, where `--input FILE` supplies the bytes of input
`NAME` (its file name). `--returns` gives each returned value's kind in order:
`bool`, `u16`, `u32`, `u64`, `f32` or `buffer:MAX_BYTES`. `--payment` is the
flat price A charges per job. The provider checks the arguments against the
program signature before calling it.

`run` saves the folder under the requester state, or at `--save-job DIR`:

```toml
format = "hellas.job.v1"

[application]
evaluator = "hellas/catena-d116170a7e66"
adaptor = "compute-0.0.1"

[payment]
price = 20

[compute]
environment = "environment.cbor"
inputs = []
objects = [{ path = "object-0.bin", object = { id = [97, 181, …], bytes = 232 } }]

[[compute.plan.calls]]
entry = "advance"
args = [{ kind = "u64", value = 2 }, { kind = "u64", value = 3 }]
bind = [{ kind = "name", value = "output-0000" }]

[[compute.plan.outputs]]
slot = "output-0000"
kind = { kind = "scalar", value = "u64" }
```

`environment.cbor` lists the sources and named assets by content ID and length;
`objects` holds the bytes the job uploads, each checked against its ID. Assets
listed in the environment but not in `objects` must already be held by the
provider. `inputs` entries have `name`, `format` and `path`.

A multi-step job is written by hand: edit a saved folder's plan. The `calls`
run once; then the provider runs `step` repeatedly, emits the `u64` in slot
`emit` after each step, and stops after a value in `stop.any_of` or after
`stop.max_steps` steps (the provider's policy also caps steps). The provider
signs one chained event per step. Step arguments may name a slot (`slot`), the
step number plus a base (`counter`), a byte range of an asset (`asset`), or a
different argument on the first step (`first-then`):

```toml
[[compute.plan.calls]]
entry = "initialize"
args = []
bind = [{ kind = "name", value = "value" }]

[compute.plan.step]
entry = "advance"
args = [
  { kind = "arg", value = { kind = "slot", value = { name = "value" } } },
  { kind = "arg", value = { kind = "u64", value = 1 } },
]
bind = [{ kind = "name", value = "value" }]
emit = "value"
stop = { any_of = [5], max_steps = 64 }

[[compute.plan.outputs]]
slot = "value"
kind = { kind = "scalar", value = "u64" }
```

The result then also carries an `emitted` output with every emitted value.

## Fetch jobs

```toml
format = "hellas.job.v1"

[application]
evaluator = "hellas/fetch-0.0.2"
adaptor = "http-0.0.1"

[payment]
price = 20

[fetch]
contract = "contract.json"
service = "http"
method = "request"
request = "request.json"
assurance = "producer-signed"
```

Use the exact evaluator/adaptor pair from the contract's manifest. The Fetch
helper requires `--contract`: `http`, the HTTPS contract built into this
release, or an exact contract file. It saves that contract and its pair, and
never takes the contract from the provider's quote; a quote, retained channel or
recovered request whose policy does not admit the job's contract is refused
before funding or payment. `request.json` is an
`HttpFetchRequest` or the selected service's JSON input. For HTTPS, the helper
supports `-X METHOD`, repeated `-H 'Name: value'`, `--data @FILE`, and
`--max-response-bytes N`. Without an explicit cap, it uses the provider's
deliverable response limit. `--tls-root FILE` supplies a DER trust anchor;
`--spki-sha256 HEX` supplies a leaf SPKI pin when the provider requires one.

Apple-attested providers require the independent `--trust-store` and
`--trust-policy` approval. Fetch additionally selects
`--assurance apple-app-attest`; raw folders declare that assurance in `[fetch]`.

## Folder rules and retries

`job.toml` and all referenced files must be ordinary files inside the folder.
Unknown keys, missing files, absolute paths, parent traversal and symlinks are
refused. File sizes are bounded before decoding or signing.

Reusing an unfinished folder resumes its signed authorization and work ID. A
successfully reported result finishes that purchase; invoking the folder again
buys a new job. A durable purchase marker retains only identifiers, price,
nonce and completion state. It contains no request or response payload.

If payment succeeded but output was lost before reporting, retry prints
`already paid (work …, price …), result lost` and refuses another charge.
`--buy-again` explicitly buys another result. It preserves the identity of an
unfinished unpaid purchase. `transact --settle --provider ENROLLMENT_ID@NODE_ID` still closes
the original channel. After finalized payment closure, the provider reclaims its
bond stake, freeing the per-client allowance for another channel. While that
reclaim is still pending, a fresh channel is refused before another owner
funding approval. A payment interrupted before acknowledgement is resolved
against the existing signed channel journal.

Fetch request/response bodies stay in memory in channel/provider journals.
An explicitly saved job folder retains caller-owned input, and selected output
files retain the caller's result. A paid Fetch result lost with the process
cannot be replayed from those journals.
