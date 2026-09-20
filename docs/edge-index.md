# Native EdgeIndex

The Explorer origin now runs a finalized EdgeIndex alongside its proof archive.
It owns global edge discovery and the complete canonical object projection; no
browser, Worker or validator has to build another global index.

Run the existing `hellas chain indexer serve` command with independently
provisioned genesis and trust files. The origin remains loopback-only. It serves:

- `GET /api/v1/edges?state=open&limit=32`
- `GET /api/v1/edges/{edge_id}?payload={payload}`
- `GET /api/v1/edges/{edge_id}/events?payload={payload}&limit=32`
- `GET /api/v1/edges/{edge_id}/evidence?payload={payload}`
- `GET /api/v1/channels/{payment_edge_id}?payload={payload}`
- WebSocket `/api/v1/edge-index/rpc`, the separate `hellas.chain.v1.EdgeIndex`
  service in `proto/hellas/chain/v1/edge_index.proto`.

HTTP supports GET/HEAD, JSON by default, and the existing protobuf Accept types.
Errors have the same negotiation and carry `IndexError`, including available
snapshot/retention metadata. RPC errors carry that protobuf in `WireStatus.details`.
`schema_version=1` is implicit for HTTP and required in RPC messages. Unknown or
repeated query fields are rejected. `funding=` explicitly requests an empty set;
without `funding`, work detail requests the sorted union of both Opens' funding.
An explicit comma-separated funding set must be unique and sorted.

`HELLAS_EDGE_SNAPSHOT_RETENTION` configures a window of 32–1024 complete snapshots
(default 32). Increasing it preserves more future snapshots; already expired pins
remain expired. Latest means the last fully materialized index snapshot. A pin
never falls forward to current data: expired pins return 410, unavailable pins
409, and an initial/incomplete index 503. IDs and list ordering are canonical raw
32-byte identifiers rendered as lowercase hex. Cursors bind identity, snapshot,
normalized filters and final position. Page limits are 1–64; JSON u64 fields are
exact decimal strings and canonical opaque bytes are base64.

Replay calls the chain's actual kernel execution and captures its public object
and registry diffs. It checks the owner commitment, QMDB state root and complete
sync target against each certified block before publication. A durable redb intent
is written before QMDB finalize; rows, history, object versions, transaction
locators and publication cursor then commit in one redb transaction. Restart
verifies the intent's certificate and publishes it only when QMDB's recovered root
matches. If QMDB still holds the preceding root, recovery drops the intent and
replays that block again. Any other root, gap or conflicting payload stops replay.

Index files and replay partitions are scoped by genesis, trust and schema. A new
scope builds from genesis/archive in a separate namespace; old data is retained.
redb holds a 64 MiB page cache. Queries retain a read transaction while versions
are pruned; in-flight readers keep their exact view. The open lookup contains live
edges and closes within the retained window, so old closed history does not slow
open discovery. Separate party/kind prefixes avoid owner enumeration. At most 16
transport queries run concurrently; query replies have a two-second deadline,
list scans also have bounded visit/time budgets, and replies are limited to 8 MiB.

The common `hellas_chain::edge_index` types, parser, cursor normalization and
`projection::EdgeIndexClient` compile for Wasm. The client checks independently
trusted block certificates, opening/closing inclusion, canonical terms and edge
identity, decoded object fields and registry bindings. It returns ordinary
reported-data types: discovery, current objects and completeness remain
**indexer-reported**. An opening certificate does not prove that its edge is still
open. Object membership/range proofs are a separate future protocol version.

For deterministic integration fixtures, run:

```sh
HELLAS_EDGE_FIXTURE_DIR=/tmp/edge-fixtures cargo test -p hellas-chain \
  --no-default-features --features explorer-origin --lib native_edge_index
```

`basic/` and `work/` each contain independent `trust.json`, `genesis.json`, a
`manifest.json` route/payload map and paired JSON/protobuf responses. The work
fixtures execute Open, Start, Response, Adjudicated, bond Timeout and Freeze on
real QMDB roots and verify all nested evidence with the client facade. The tests
also cover stable pagination, pin expiry, old in-flight readers, gap/parent/root
refusal, restart on both sides of QMDB finalize, and a large cold closed index.
