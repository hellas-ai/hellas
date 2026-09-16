# Verified explorer

`hellas-chain/verified-explorer` verifies consensus-backed block and address proofs.
The included native origin follows the chain archive and listens only on loopback.

Provision a `hellas_genesis::TrustDocument` independently of the RPC peer. It has
`schema_version: 1`, `network_id: "hellas-devnet-1"`, the SHA-256 of the exact
genesis JSON bytes, and a nonempty contiguous epoch schedule. Each epoch supplies
an ID, a height range, and the 96-character compressed BLS MinPk threshold
identity. Schedules start at height zero, have no gaps or overlaps, and use
strictly increasing IDs. A finite final range rejects later heights until the
trust document is updated.

`trust_sha256` is the SHA-256 of `serde_json::to_vec(&TrustDocument)`. Its
canonical form has no whitespace; document fields are ordered
`schema_version,network_id,genesis_sha256,epochs`, and epoch fields are ordered
`epoch,start_height,end_height,threshold_identity`. Validated strings are ASCII
and integer fields use unsigned decimal without padding. Install the exact trust
document with every verifier; a document retrieved from the proof origin is not
a trust anchor.

`ProofBundle` has matching JSON and protobuf fields. `ExplorerVerifier::verify`
checks the trust identifier, network, epoch, threshold certificate, canonical
block bytes, payload, height, state root, and requested block or transaction.
Transaction IDs are SHA-256 hashes of the canonical chain transaction encoding.
`observed_at_ms` is advisory: a valid proof does not establish that it is the
newest available answer.

Address summaries and holdings pages use `AddressProofBundle`. Its bounded page
is a JSON-encoded `OwnerPageProof` linked to the owner root in the certified
block. `verify_address` checks the certificate and proof before exposing a
`VerifiedAddress`. Summary `balance` is the sum of spendable coins; `count`
includes coins and edges, while edges contribute zero balance. It makes no claim
about complete transaction history.

Consensus updates the sparse owner tree in the same speculative QMDB batch as
coin and edge mutations. Canonical `HLS2` blocks commit both the QMDB state root
and the owner root. The new QMDB partition format requires fresh devnet and
native-follower storage; old block encodings cannot be replayed with it.

Owner paths prove membership or absence. Holdings paths include authenticated
subtree counts, so a page cannot omit, reorder, duplicate, or substitute a
holding. Limits are 1 through 64. The origin rebuilds owner snapshots from
verified retained history and publishes a snapshot only after its root matches
the certified block.

## Run the native origin

For a disposable devnet, export the public epoch-zero trust from the generated
validator configuration:

```sh
hellas-cli chain validator export-trust --config network/validator-0.toml --genesis network/genesis.json > network/trust.json
hellas-cli chain indexer serve --rpc ws://127.0.0.1:8789 --genesis network/genesis.json --trust network/trust.json --storage-dir network/indexer
```

The exporter checks the genesis against the validator configuration and emits
public trust data. Authenticate `network/trust.json` and the exact genesis file
separately from the RPC peer. Do not parse, reserialize, trim, or otherwise
change the provisioned genesis bytes.

`ExplorerVerifier::with_genesis(trust, genesis_bytes)` pins both inputs.
`ExplorerVerifier::new(trust)` and `chain indexer serve` without `--genesis` use
the embedded devnet genesis.

`hellas-cli chain indexer serve --rpc wss://relay.example/ws --trust trust.json
--storage-dir /var/lib/hellas/explorer --listen 127.0.0.1:8788` starts the local
origin. Publish or protect that loopback service with your normal deployment
infrastructure. The process never downloads trust configuration from the RPC
peer.

`/api/v1/blocks/{latest|height|payload}/proof` and
`/api/v1/transactions/{digest}/proof` return `ProofBundle`. Proof routes default
to protobuf and return JSON for `Accept: application/json`; both
`application/x-protobuf` and `application/protobuf` are accepted. Other aliases
default to JSON. Unknown representations receive 406. Transaction locators
rebuild from the verified archive on restart; unavailable or not-yet-indexed
locators return 503. Add `?height=N` to resolve a transaction without waiting
for its locator.

`/api/v1/addresses/{base58-owner}/proof?offset=0&limit=64` returns an address
bundle. `payload=...` pins a snapshot for pagination and returns 503 once that
snapshot falls outside the origin's 32-snapshot window. Snapshots are indexed by
payload and height, reject conflicting bindings, and are rebuilt from the
durable finalized archive after a restart.
