# Verified explorer

`hellas-chain/proof-verify` verifies consensus-backed block and address proofs.
The included native origin follows the chain archive and listens only on loopback.

Provision a `hellas_genesis::TrustDocument` independently of the RPC peer. It has
`schema_version: 1`, `network_id: "hellas-devnet-2"`, the SHA-256 of the exact
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

`ProofBundle` has matching JSON and protobuf fields. `ProofVerifier::verify`
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
is a typed `OwnerPageProof` linked to the owner root in the certified
block. JSON and protobuf responses carry the same page fields. `verify_address` checks the certificate and proof before exposing a
`VerifiedAddress`. Summary `balance` is the sum of spendable coins; `count`
includes coins and edges, while edges contribute zero balance. It makes no claim
about complete transaction history.

Consensus updates the sparse owner tree in the same speculative QMDB batch as
coin and edge mutations. Canonical `HLS3` blocks commit both the QMDB state root
and the owner root.

Owner paths prove membership or absence. A Latest page carries an authenticated
after-key path, including when that key has been removed; subtree counts prove
the exact next rank. A page cannot omit, reorder, duplicate, or substitute a
holding. Financial selection reads pages until it finds enough candidates and
rechecks selected objects together at one current root. Complete human listings
report a changed root and can be retried. Limits are 1 through 32, matching the Current proof key budget. The
origin reads owner nodes from the durable
QMDB checkpoint shared with finalized EdgeIndex replay. It publishes a checkpoint
only after deterministic replay matches the certified state and owner roots.

## Run the native origin

For a disposable custom network, give generated genesis a fresh `--network-id`
and export the public epoch-zero trust from the validator configuration. A
registered network ID must keep its shipped genesis:

```sh
hellas chain validator export-trust --config network/validator-0.toml --genesis network/genesis.json > network/trust.json
python3 - <<'PY'
import json
from pathlib import Path
root = Path("network")
profile = {
    "genesis_json": (root / "genesis.json").read_bytes().decode("utf-8"),
    "trust": json.loads((root / "trust.json").read_text()),
    "validators": ["ws://127.0.0.1:8789"],
}
(root / "chain.json").write_text(json.dumps(profile))
PY
hellas --chain-config network/chain.json chain indexer serve --rpc ws://127.0.0.1:8789 --home network/indexer
```

The exporter checks the genesis committee against the validator configuration
and emits public trust data. Authenticate `network/trust.json` and the exact genesis file
separately from the RPC peer. Put the trust document, validator URLs, and exact
genesis bytes as a JSON string in `network/chain.json` before starting the indexer.
Do not parse, reserialize, trim, or otherwise change the
provisioned genesis bytes when calculating its exact-file SHA-256.

CLI chain queries and signing commands for this custom network also require
`--chain-config network/chain.json`. The RPC client authenticates snapshot
height and roots by fetching the canonical
block committed by its certificate. Coin, edge, and owner listings carry
Current-state inclusion, exclusion, and owner-rank proofs checked by
`ProofVerifier` against the selected epoch schedule. The CLI labels raw
validator and finalization metadata as unverified.

`ProofVerifier::with_genesis(trust, genesis_bytes)` pins the full document;
`ProofVerifier::with_digest(trust, canonical_digest)` accepts a derived
light-client pin. Without `--chain-config`, CLI commands
select the compiled Devnet profile.

`hellas --chain-config chain.json chain indexer serve --rpc wss://relay.example/ws
--home /var/lib/hellas/explorer --listen 127.0.0.1:8788` starts the local
origin over a full executing chain node. Repeat `--rpc` for multiple validator
or relay seeds; the node also discovers iroh ChainSync peers from its provisioned
committee. Trust and genesis are always provisioned locally. Publish or protect
the loopback API with your deployment infrastructure.

The node executes finalized blocks through the validator kernel and checks
state and owner roots before publishing the read index. The complete block
archive is retained by default; `--chain-archive-blocks N` exposes the last N
executed blocks and reclaims older storage in sections. Fresh nodes replay from
genesis and require sources retaining the missing history. Paid consumers read
this same local state. Grant-only processes do not start a chain node.

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

`/api/v1/addresses/{base58-owner}/proof?offset=0&limit=32` returns an address
bundle. `payload=...` pins the current durable owner checkpoint. The origin serves
only that checkpoint, so a new finalized block makes an older pin unavailable,
including between pagination requests. EdgeIndex and owner proofs both use the
current checkpoint. The Worker may cache older verified pages, but cannot generate
uncached pages for an old native checkpoint.

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
