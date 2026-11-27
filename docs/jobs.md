# Jobs

Every job command runs one job in one of three ways: under an access file
someone shared with you (`--access FILE`), paid (`--pay MAX --provider
ENROLLMENT_ID@NODE_ID`), or on this machine (`--local`, GPU builds only). To
run an existing job folder under a grant:

```sh
hellas transact --job ./job --access friend.access --output ./result
```

The access file is checked against this home's principal and device. The grant
route checks the provider pin from its signed offer, the device-bound credential
and the resource's invocation policy. It starts no chain client and spends no
coins; the job folder's price is used only by paid execution and can be zero for
a grant job. The offer's single policy selects the resource; `--resource ID`
selects one when it has several. Reusing the same access file and job returns
its retained result without executing again. An unresolved attempt reports its
recorded status instead of submitting new work. A new attempt path (`--attempt
FILE`) is an explicit request to execute again and consume the allowance.
`run`, `image`, `transcribe`, `speak`, `decide`, `text` and `fetch` accept `--access FILE` as the
alternative to `--pay`; they save a zero-price job and use this same route.
Grant channel journals and attempts live under `<home>/grants`; paid execution
lives under `<home>/chains/<full consensus digest>/`.
Grant Compute uses ephemeral provider retention for job payloads. Compiled
programs are cached independently of payload retention. A signed failed result
makes the command fail on both first delivery and saved-result replay.

With the compute-enabled package (`cli-cuda`, `cli-hip`, the NixOS module or the CUDA/HIP images;
the portable release has no local compute), every Compute command also accepts
`--local`: the job runs on this machine's executor under your own limits, with
no chain, channel, grant or attempt record. A helper serves the model's weights
from its local checkpoint or pinned Hub source; `run` and `transact --job` read assets
through `--content PATH` or `--content-config`. `--timeout` bounds it like any other job.

```sh
hellas transcribe --model hf://unsloth/whisper-tiny@34457cb234c8624f23ac716000773b367000df6e --audio speech.wav --local
hellas text --model hf://ggml-org/Qwen3-0.6B-GGUF@afe8ad3577aa22500b3cd1c880f153b3b0e1cae8/Qwen3-0.6B-BF16.gguf --prompt 'Why is the sky blue?' --local
```

To follow the default branch for one invocation, omit the revision.

```sh
hellas transcribe --model hf://unsloth/whisper-tiny --audio speech.wav --local
```

A branch or tag can follow the repository name after `@`. Encode a slash in the ref name as `%2F`. An optional file path can follow any revision or the repository name. The CLI prints the resolved commit to stderr and uses it for the entire command. A gateway resolves each ref once at startup. Use the printed SHA to repeat a job. To pre-acquire assets, `hellas store acquire` accepts the same Hub locator or a Hugging Face web URL, locks the ref to one commit, and prints the commit, content ID and root name.

The [Nix one-liners](nix.md#local-gpu-one-liners) include pinned commands for text, transcription, MMS speech, Flux images and
one gateway serving them together. The same `cli-cuda` or `cli-hip` output
runs every modality; no development shell is needed.

A Compute job names the evaluator its program is rendered for. Remote Compute
commands render for `--backend EVALUATOR`, the id the provider's GPU runtime
registers (such as `hellas/catena-dfad87438018-hip-gfx1151`), before they ask for a
quote; the provider refuses a program for an evaluator it did not register.
The id names the architecture of the device the runtime opened, because the
same program rounds differently on different architectures.
`--local` renders for this machine's GPU runtime.

`hellas text --model MODEL --prompt TEXT [--system TEXT] [--max-tokens N]`
renders one chat turn with the GGUF's tokenizer and embedded Jinja chat template,
runs it as a Compute job
and prints the decoded reply.

A pinned Hub GGUF works with `text`, `decide`, `program` and the gateway. Give the 40-hex revision and the file path when the repository holds multiple GGUFs.

```sh
hellas text --model hf://LiquidAI/LFM3-1.7B-GGUF@cd0c74c575b5c416f3011b5b4c298077f26ca8c2/LFM3-1.7B-BF16.gguf --prompt 'What is the capital of France?' --local
```

With a published Xet ID, the remote buyer reads only the header. For a Git or LFS weight file without a published Xet ID, the buyer streams the pinned file once to compute its canonical content ID and reads headers from that download. The provider can pre-acquire the file, or configure its content allow-list with the same repository, revision, file path, content ID and size. For example:

```sh
hellas store acquire hf://LiquidAI/LFM3-1.7B-GGUF@cd0c74c575b5c416f3011b5b4c298077f26ca8c2/LFM3-1.7B-BF16.gguf --expect a4896de517cae418383c2fd9954bc5ac33d8112b810c7895fb3feb70dca622dc --bytes 3466626336 --policy jobs
```

The provider can use pre-acquired content or fetch missing content from its
allow-list after the policy check. Grant and paid rules match the same
model and program IDs regardless of the source.

The provider checks the published Xet hash against the canonical content ID. It rejects files published with legacy Xet chunking. With `--local`, the local executor acquires the weights into its own content store.

A program commits to a model ID covering its named checkpoint files and render
metadata. An activated provider stores their catalog in
`models/by-id/MODEL_ID` with the `jobs` policy. To permit peer reads of the
whole model, the owner can list the catalog's tree ID and byte size, then set
its pin to `public`:

```sh
hellas store pin ls models/by-id
hellas store pin set models/by-id/MODEL_ID TREE_ID --bytes TREE_BYTES --tree --policy public
```

Use `hellas program --model-id MODEL` to print its reference without selecting an evaluator.
With a public catalog, pass `--model hellas://MODEL_ID` to a job command. The
buyer contacts the node in its signed access offer or the node selected by
`--provider`. To specify a source explicitly, including with `hellas program`
or a gateway route, use `hellas://MODEL_ID@NODE_ID` or
`hellas://MODEL_ID@NODE_ID@IP:PORT`. The buyer verifies the catalog against the
model ID and reads authenticated ranges for checkpoint headers and metadata.
Publishing the tree permits readers to download every file in it, including
weights. For private sharing, the owner can choose `--policy granted` and give the
access credential `content.read` on the exact catalog pin. A job addressed by
`--access` uses that authenticated connection when the catalog is private.
A compute grant alone authorizes execution only.

`hellas transact --job DIR` executes a caller-owned job folder for any
application. `hellas run` (one call of a Catena program) and `hellas fetch`
(one HTTPS request) build such a folder and go through the same SDK
transaction. Requesters run no node: they keep local signing keys and
wallet/channel metadata, and chain reads use authenticated validator RPCs.
Within a connection, requester clones share a verified object view in memory.
The first read downloads a certified state snapshot; later reads verify only
new operation ranges, rebuilding the view if pruning overtakes its cursor.
Signing keys and funding/channel recovery journals remain durable.

```sh
hellas faucet
hellas run --provider ENROLLMENT_ID@NODE_ID --source counter.hex --entry advance \
  --arg u64:2 --arg u64:3 --returns u64 --backend hellas/catena-dfad87438018-hip-gfx1151 \
  --pay 20 --save-job ./add
hellas transact --job ./add --provider ENROLLMENT_ID@NODE_ID@127.0.0.1:9000 -o ./result
hellas fetch https://example.com/data --provider ENROLLMENT_ID@NODE_ID --pay 20 \
  --contract http --spki-sha256 LEAF_SPKI_SHA256 --save-job ./request -o ./response
hellas transact --settle --provider ENROLLMENT_ID@NODE_ID
```

`--provider` takes the address `hellas serve` prints: the content ID of the
provider's enrollment bundle and the node ID it binds, optionally followed by
`@IP:PORT`. Quotes, funding, payment and every reconnect refuse a provider that
presents any other enrollment, before anything is signed or funded.

Paid jobs act for the home's principal key, `<home>/principal.key`, created on
first use; `--passkey FILE` points at a key held outside the home. `hellas
faucet [--amount N]` pays it devnet coins from a random public faucet account
and waits until the payment is final. The default chain is the shipped devnet. Select a compiled chain with
`--chain devnet`, or pass one authenticated JSON profile with `--chain-config FILE`.
The profile contains the exact `genesis_json` bytes as a JSON string, `trust`,
and a nonempty `validators` URL list. `--timeout 90s` bounds the whole operation;
without it the command waits until the job is done. `--home DIR` selects the directory for identity and requester state.

A helper asks for the provider's quote first, refuses a price above `--pay
MAX`, and builds the job at exactly the quoted price. A saved `transact --job`
keeps its own signed price, which must equal the quote. The authenticated quote
must admit the application's exact manifest. Those checks and the advertised input limits run before new channel funding.
Fetch's encoded-input size check uses the largest purchase-nonce encoding,
reserving up to 32 bytes more than a particular purchase needs. One owner
approval funds the quoted channel amount; later jobs reuse its balance.
`--settle` closes the channel after the job. With no `--job`, it discovers
retained channels from signed local journals, keyed by their exact bonds, and
closes them using verified finalized blocks. This path resumes an interrupted close without
contacting the provider, reading live object proofs or requesting new funding.
Missing, corrupt or mismatched journals stop settlement rather than being
silently replaced.

## What each application proves

Execution identity is one canonical `ProgramManifest`: `(evaluator, adaptor,
content-addressed application root)`. The two application identifiers are exact
opaque strings. Hellas does not parse versions, negotiate compatibility, or
consult a model or package registry.

The application owns the meaning of its root. The two applications
intentionally have different trust boundaries:

| Application | Root and trusted computation | Outside that guarantee |
| --- | --- | --- |
| `hellas/catena-dfad87438018-<runtime>-<arch>` (the id a GPU runtime registers for the device it opened, such as `-hip-gfx1151` or `-cuda-sm_120`), `compute-0.0.1` | The GPU runtime and device architecture the program is compiled for, exact Catena Hex sources, named content-addressed assets, inputs, the call plan (calls, optional step loop and stop rule) and declared outputs | Where sources and weights come from, tokenizer, chat template, text decoding, and API presentation |
| `hellas/fetch-0.0.2`, the contract's adaptor (`http-0.0.1`, `codex-responses-0.0.2` or `openai-responses-0.0.3`) | A strict stateless Responses field set; typed reconstruction of provider-shaped JSON; `stream=true` and upstream `store=false`; the exact official Codex or OpenAI HTTPS endpoint; no redirects; and SSE response projection | The truth, correctness, and availability of the adversarial upstream service; provider route label; credentials/auth-file location; and access policy |

Fetch's purpose is to attest the exact transformation around a
remote request, so structuring and destructuring are inside that application's
trusted path rather than presentation performed outside it. This proves which
checks and transformation ran, not that the remote service's claims are true.

A platform-backed Assurance authenticates the Fetch application. The
`ProducerSigned` mode authenticates only the producer key and signed transcript;
it does not authenticate a running binary. The sealed Responses adaptor sends
`store=false` upstream and accepts text and client-executed function tools.

Work is the execution protocol for payment-funded channels and owner, principal
and delegated grants, including gateways and sealed Fetch. Accepted
paid inputs and results remain in the channel's recovery/evidence journal,
independently of gateway archive settings.

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
`bool`, `u16`, `u32`, `u64`, `f32` or `buffer:MAX_BYTES`. `--pay MAX` is the
most you accept for the provider's flat per-job price. The provider checks the arguments against the
program signature before calling it.

Sources must be self-contained: include every stdlib definition the program
uses. The provider compiles exactly the shipped sources with the named
evaluator, including on a cache miss or preflight; it supplies no implicit
stdlib. Model packages bundle the client's stdlib and model into one Hex
source, pruned using catena-models' reachability policy. The resulting bytes
are part of the job's content identity.

`run` saves the folder under the requester state, or at `--save-job DIR`:

```toml
format = "hellas.job.v1"

[application]
evaluator = "hellas/catena-dfad87438018-hip-gfx1151"
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

## Image jobs

Use a pinned Flux2 Klein checkpoint. The client reads the published tensor headers,
configuration and tokenizer. The provider acquires the original weight files
and the model's GPU setup prepares the text encoder, denoiser and VAE.
The default image variant is 512×512 with four steps. A local snapshot can
include `variants.json` with 1–64 unique width, height and step configurations.
Variant settings are part of the model ID. `hellas program` prints the
exact program for each allowed variant.

```sh
nix run github:hellas-ai/hellas#cli-cuda -- image --model hf://black-forest-labs/FLUX.2-klein-4B@e7b7dc27f91deacad38e78976d1f2b499d76a294 --prompt 'a small red fox' --seed 42 --width 512 --height 512 --steps 4 --local -o fox.png
```

Use `cli-hip` for AMD. Both outputs include the Compute CLI and runtime compiler.

For 512×512 images, the provider must admit a 3 MiB output; allow 2 MiB of
uploads for the program, token IDs and noise. Set its execution budget for
the selected hardware and step count.

```sh
hellas image --provider ENROLLMENT_ID@NODE_ID --model hf://black-forest-labs/FLUX.2-klein-4B@e7b7dc27f91deacad38e78976d1f2b499d76a294 \
  --prompt 'a small red fox' --seed 42 --width 512 --height 512 --steps 4 \
  --backend hellas/catena-dfad87438018-hip-gfx1151 --pay 20 -o fox.png
```

`image` saves the job before purchase, writes the PNG to `-o` (default
`image.png`), and saves its signed result under the job folder's `result/`.
One job runs `flux.encode-text`, `flux.denoise` and `flux.decode-image`, passing
conditioning and latents in slots. Tokenization and seeded ChaCha8 noise are
client inputs; PNG encoding is client presentation of the signed RGB buffer.

Start the gateway with the same pinned checkpoint and use its repository name in the image request.

```sh
hellas gateway --model hf://black-forest-labs/FLUX.2-klein-4B@e7b7dc27f91deacad38e78976d1f2b499d76a294 --bearer-file ./gateway.bearer
curl http://127.0.0.1:8080/v1/images/generations \
  -H "Authorization: Bearer $(cat ./gateway.bearer)" -H 'Content-Type: application/json' \
  -d '{"model":"FLUX.2-klein-4B","prompt":"a small red fox","seed":42,"size":"512x512","steps":4}'
```

The response contains `data[0].b64_json` and signed evidence in `hellas`.
A local checkpoint uses the directory name. Width and height must each be
multiples of 16 from 16 through 512 and steps must be 1–50. Requests must match
a package variant. Request defaults are 512×512, four steps and seed zero. The API accepts one image (`n: 1`) in `b64_json`
format; unsupported fields are rejected before work starts.

## Decision jobs

Ask a d1 model a yes-or-no question on the local GPU:

```sh
echo '{"state":"I was charged twice.","questions":{"billing":{"type":"noul","instructions":"Is this about billing?"}}}' | hellas decide --model hf://LiquidAI/d1-2B-GGUF@4a181094d1b6addfaa3a0956f78e7ab2aa406a0c/d1-2B-BF16.gguf --local
```

A d1 decision model answers questions about a state without generating text.
Its BF16 GGUF supplies the weights and request metadata. A
provider adds the GGUF with `route add`, as for a text model.

The request names a `state` (a string or any JSON value) and one or more
`questions`, each of type `noul` (yes or no), `choice` or `score`:

```json
{
  "state": "I was charged twice this month, please refund one of them.",
  "questions": {
    "refund": {"type": "noul", "instructions": "Is the customer asking for a refund?"},
    "team": {
      "type": "choice",
      "instructions": "Which team should handle this?",
      "criteria": {"billing": "Charges, refunds, invoices", "technical": "App or site faults"}
    },
    "urgency": {
      "type": "score",
      "instructions": "How urgent is this?",
      "criteria": ["Can wait", "Today", "Blocking the customer now"]
    }
  }
}
```

```sh
hellas decide --provider ENROLLMENT_ID@NODE_ID --model hf://LiquidAI/d1-2B-GGUF@4a181094d1b6addfaa3a0956f78e7ab2aa406a0c/d1-2B-BF16.gguf \
  --request request.json --backend hellas/catena-dfad87438018-hip-gfx1151 --pay 20
```

`decide` reads the request from `--request FILE`, or from standard input by
default, and prints the response JSON:

```json
{
  "model": "d1-2B-BF16",
  "answers": {
    "refund": {"type": "noul", "noul": 0.97},
    "team": {"type": "choice", "choice": "billing", "confidence": 0.99, "probabilities": {"billing": 0.99, "technical": 0.01}},
    "urgency": {"type": "score", "score": 1.0, "confidence": 0.6, "probabilities": {"0": 0.1, "1": 0.6, "2": 0.3}, "legend": {"0": "Can wait", "1": "Today", "2": "Blocking the customer now"}}
  },
  "usage": {"input_tokens": 212, "output_tokens": 0}
}
```

The client expands each question into one complete prompt, using the request
format stored in the GGUF. One job then runs `qwen3.init` and `qwen3` once per
question and returns each prompt's final vocabulary logits; the client reads
the answers from them. A job answers at most 64 questions. The provider must
admit two bytes of output per vocabulary entry for each question (256 kB per
question for d1) and uploads for the program and token IDs.

Requests are text only: `images` and `files` are rejected before work starts.
The response names the model by its file name without the extension, as a
gateway route does; a request's optional `model` must match it.

The gateway exposes the same model with `gateway --model d1.gguf` and
`--access`, `--pay` or `--local` as usual. `POST /v1/systemone` takes the same
body, with `model` set to the package's file name without its extension, and
returns the same response with signed evidence in `hellas`:

```sh
curl http://127.0.0.1:8080/v1/systemone \
  -H "Authorization: Bearer $(cat ~/.hellas/gateway/bearer)" -H 'Content-Type: application/json' \
  -d "$(jq '.model = "d1"' request.json)"
```

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
`--max-response-bytes N`. The provider uses the credential whose configured
origin, path and method cover the request, or sends it without a credential when
none applies. The request carries no credential selector or provider secret.
Without an explicit cap, it uses the provider's deliverable response limit.
`--tls-root FILE` supplies a DER trust anchor;
`--spki-sha256 HEX` supplies a leaf SPKI pin when the provider requires one.

A configured gateway `GET /v1/models` passthrough takes precedence over generated
model discovery. Other configured methods on that path keep their normal routing.

Apple-attested providers require the independent `--trust-store` and
`--trust-policy` approval. Fetch additionally selects
`--assurance apple-app-attest`; raw folders declare that assurance in `[fetch]`.

### Sealed Fetch

Fetch route names are operator-defined routing labels. The sealed destination
selects the trusted adaptor, fixed official endpoint, no-redirect HTTP driver,
and response projector as one unit. A configuration cannot supply a URL or
claim a different adaptor identity.

A provider's daemon document contains Fetch backend entries with a service,
method, upstream and write-only credentials. `backend add` and `route add`
create OpenAI-compatible HTTP entries; embedding applications can also select
a sealed Responses backend. Work authorization comes from the mounted grant
or paid channel. There is no separate Fetch configuration file.
See [paid Work](../crates/channel/README.md) for channel configuration and
[HTTPS Fetch](../crates/providers/HTTPS.md) for provider credentials and egress.

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
the original channel. After finalized payment closure, whichever party sees it
first returns the provider's bond stake by its Timeout, freeing the per-client
allowance for another channel. While that reclaim is still pending, a fresh
channel is refused before another owner funding approval. A payment interrupted before acknowledgement is resolved
against the existing signed channel journal.

Fetch request/response bodies stay in memory in channel/provider journals.
An explicitly saved job folder retains caller-owned input, and selected output
files retain the caller's result. A paid Fetch result lost with the process
cannot be replayed from those journals.

## Tracked native execution

Compute job and attempt digests include the evaluator.

The SDK's `execution` module provides `ExecutionAttempt` and a borrowed
`ExecutionSession` for paid or granted work without an HTTP listener. Open an
attempt at a caller-owned private path with the original `JobInput` and exact
`ExecutionTerms`. For a new paid attempt, `open_paid_session` binds the target
before selecting its channel. A retained channel uses its signed policy without
a fresh quote or funding approval; a zero funding cap permits that reuse.
Fresh funding checks the actual quote and approval before owner signing. Grant callers use
`open_grant_session` with the selected resource. Use a new path for each
intentional execution; an existing path binds the original input, target and
terms and cannot be used to buy again.

After interruption, use `open_existing`, inspect the local facts, and call
`recover` on the bound session. Recovery does not propose another job or fund
another channel. Acceptance, terminal evidence, payment, result availability
and delivery acknowledgement are separate facts. A grant can be accepted while
still pending; a paid job can be complete even if its output is unavailable.
Neither situation authorizes a replacement execution. Call `retain_results(true)`
when opening the attempt to opt into private result retention; after delivering a
verified retained result, call `reported`. The acknowledgement survives result
removal and does not erase the terminal status. Without retained bytes, callers
must handle unavailable output independently from execution and payment status.
Paid tracked markers store a stable per-attempt nonce and the expected request
commitment, without request payloads. Recovery can use the channel's signed
acceptance to restore a work ID lost between the channel journal commit and the
caller marker update. It preserves the original nonce and does not execute or
fetch the job again. A missing acceptance or a proposal without the provider's
signature leaves acceptance unknown and payment pending.

The attempt nonce is part of the signed request commitment, so an acceptance
at a reused channel nonce for identical input is not mistaken for this
attempt's. A marker without its attempt nonce, or a proposed marker without its
request commitment, is refused rather than recovered.

The executable [native grant example](../crates/sdk/tests/native_execution/grant.rs)
and [paid tracked regressions](../crates/sdk/tests/paid_e2e/tracked.rs)
exercise tracked execution, recovery and acknowledgement.

The CLI persists the same attempt identity. `--buy-again` deliberately creates a
new attempt and retains the previous tombstone. Payment is fixed per job; the
channel funding amount is separate from the job price.
