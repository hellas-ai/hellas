# Paid jobs

`hellas transact` executes a caller-owned job folder. `hellas fetch` builds the
same folder and uses the same SDK transaction. Requesters keep local signing
keys and wallet/channel metadata; chain reads use authenticated validator RPCs.

```sh
hellas --passkey owner.key transact --job ./job --provider NODE_ID@127.0.0.1:9000 -o ./result
hellas --faucet fetch https://example.com/data --provider NODE_ID --payment 20 \
  --spki-sha256 LEAF_SPKI_SHA256 --save-job ./request -o ./response
hellas --passkey owner.key transact --settle --provider NODE_ID
```

`--faucet` retains a selected public devnet account beside the identity;
`--faucet-account N` selects one explicitly. These are public development keys.
The default chain is the shipped devnet. A custom chain uses `--trust FILE`,
`--genesis FILE`, and six repeated `--validator URL` options. `--timeout 300s`
bounds the whole operation. `--state-dir DIR` selects requester state.

The authenticated quote must admit the application's exact manifest and price.
Those checks and the advertised input/generation limits run before new channel
funding. Fetch's encoded-input size check uses the largest purchase-nonce
encoding, reserving up to 32 bytes more than a particular purchase needs. One owner approval funds the
quoted channel amount; later jobs reuse its balance. `--settle` closes the
channel after the job. With no `--job`, it closes retained channels without
requesting new funding.

## Folder format

`job.toml` and all referenced inputs must be ordinary files inside the folder.
Unknown keys, missing inputs, absolute paths, parent traversal and symlinks are
refused. Input sizes are bounded before decoding or signing.

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
helper saves that pair and the admitted contract from the provider's quote;
`--contract FILE` explicitly selects the same contract. `request.json` is an
`HttpFetchRequest` or the selected service's JSON input. For HTTPS, the helper
supports `-X METHOD`, repeated `-H 'Name: value'`, `--data @FILE`, and
`--max-response-bytes N`. Without an explicit cap, it uses the provider's
deliverable response limit. `--tls-root FILE` supplies a DER trust anchor;
`--spki-sha256 HEX` supplies a leaf SPKI pin when the provider requires one.

Apple-attested providers require the independent `--trust-store` and
`--trust-policy` approval. Fetch additionally selects
`--assurance apple-app-attest`; raw folders declare that assurance in `[fetch]`.

## Retries and outputs

Reusing an unfinished folder resumes its signed authorization and work ID. A
successfully reported result finishes that purchase; invoking the folder again
buys a new job. A durable purchase marker retains only identifiers, price,
nonce and completion state. It contains no request or response payload.

If payment succeeded but output was lost before reporting, retry prints
`already paid (work …, price …), result lost` and refuses another charge.
`--buy-again` explicitly buys another result. It preserves the identity of an
unfinished unpaid purchase. `transact --settle --provider NODE_ID` still closes
the original channel. After finalized payment closure, the provider reclaims its bond stake, freeing
the per-client allowance for another channel. While that reclaim is still
pending, a fresh channel is refused before another owner funding approval. A
payment interrupted before acknowledgement is resolved against the existing
signed channel journal.

Fetch request/response bodies stay in memory in channel/provider journals.
An explicitly saved job folder retains caller-owned input, and selected output
files retain the caller's result. A paid Fetch result lost with the process
cannot be replayed from those journals.

`fetch -o FILE` writes the raw HTTPS response body; without `-o` it writes that
body to stdout and its payment report to stderr. `transact -o DIR` writes the
signed transcript, result identifiers and decoded output. Its report identifies
the provider signature and binding to this job. Hellas does not re-run the job.
