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

`VerifiedStore` backends retain immutable canonical evidence and a monotonic head
cursor. Historical cache fills cannot move that cursor backward, and eviction
cannot erase it. Reverify stored evidence against independently provisioned trust
before rendering; the shared storage interface permits native and Worker backends.

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
holding. Limits are 1 through 64. The origin reads owner nodes from the durable
QMDB checkpoint shared with finalized EdgeIndex replay. It publishes a checkpoint
only after deterministic replay matches the certified state and owner roots.

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
default to JSON. Unknown representations receive 406. EdgeIndex commits transaction
locators durably alongside finalized replay; unavailable or not-yet-indexed
locators return 503. Add `?height=N` to resolve a transaction without its locator.
Block and transaction evidence is reverified before serving. Owner checkpoints
are certified on admission and reverified on disk recovery; address pages are
verified against that immutable checkpoint without repeating its signature check.

`/api/v1/addresses/{base58-owner}/proof?offset=0&limit=64` returns an address
bundle. `payload=...` pins the current durable owner checkpoint. The origin serves
only that checkpoint, so a new finalized block makes an older pin unavailable,
including between pagination requests. EdgeIndex's retained discovery snapshots
do not extend owner-proof retention. The Worker may cache older verified pages,
but cannot generate uncached pages for an old native checkpoint.

An unavailable pin returns HTTP 409 with `Cache-Control: no-store`, `Vary: Accept`,
and a typed JSON/protobuf error containing `schema_version`, `network_id`,
`code: "snapshot_unavailable"`, `message`, and `latest_url`. Follow that URL
explicitly to restart pagination from latest holdings; the origin never silently
substitutes another snapshot. For protobuf responses, HTTP 409 carries
`OwnerSnapshotError`, while HTTP 200 carries `AddressProofBundle`. An unpinned
request returns 503 when no verified owner snapshot is available yet.

On restart, the origin recovers the QMDB/index publication intent and verifies
the certificate, canonical block, state root, sync-target root/range, and durable
owner root before listening. It serves holdings from disk and resumes replay at
the next height; restoring owner proofs needs no archive rebuild. A replay mutex
and one QMDB read guard bind each page to one committed checkpoint. Block history
still uses the separate durable Commonware archive.
