# Native EdgeIndex

The Explorer origin runs a finalized EdgeIndex alongside its Commonware follower archive.
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
current snapshot metadata. RPC errors carry that protobuf in `WireStatus.details`.
`schema_version=2` is implicit for HTTP and required in RPC messages. Unknown or
repeated query fields are rejected. `funding=` explicitly requests an empty set;
without `funding`, work detail requests the sorted union of both Opens' funding.
An explicit comma-separated funding set must be unique and sorted.

The index serves **current channel state plus complete event history**. Latest
means the last fully materialized checkpoint. A state pin or pagination cursor
must match that checkpoint; after publication advances, requests return typed
409 `snapshot_unavailable` with the current checkpoint in the error envelope.
Consumers explicitly restart at latest rather than silently mixing checkpoints.
An initial/incomplete index returns 503. `retained_from_height` equals the current
checkpoint height; there is no state-retention window or retention setting.
Durable data inconsistencies return 500 `index_corrupt`, and storage failures
return 500 `index_storage_error`; RPC maps both to `Internal`. Admission, deadline
and scan-budget exhaustion remain transient 503 responses.

Closed-channel details, every edge event, transaction locator and opening/closing
certificate remain available. Historical block and transaction proof routes are
unchanged. Only querying what the channel state used to be at an old checkpoint
is unsupported. An already running read keeps its coherent redb transaction.

IDs and list ordering are canonical raw 32-byte identifiers rendered as lowercase
hex. Cursors bind identity, checkpoint, normalized filters and final position.
Page limits are 1–64. EdgeIndex JSON uses nested `envelope` and `data` objects;
message unions use ordinary externally tagged Serde objects under `answer` or
`terms`. EdgeIndex u64 fields are exact decimal strings, and all byte fields
(including addresses) use base64. HTML displays addresses as base58 links.
The reused schema-1 proof objects retain numeric integers and byte arrays.

Schema 2 includes each canonical block proof once per response. The snapshot
proof remains in `snapshot.block_proof`; `evidence` contains distinct historical
proofs sorted by payload. Open/close references resolve against the decoded
`VerifiedBlock` views retained by `projection::verify_metadata`; each certificate
and block is verified once per response. Opening and closing objects do not embed
additional proofs. A bond detail that names an associated payment also includes that
payment's opening proof: clients check its edge ID, referenced bond and embedded bond
terms. Derived links must match those checked fields. A missing reverse association
is still an indexer-reported discovery claim, not authenticated absence.
Both transports use the same generated message definitions and JSON
adapters from `hellas-rpc`; no protobuf transcode sits between RPC and the index.
The standalone block/address proof API remains schema 1 with its existing JSON.

Replay calls the chain's actual kernel execution and captures its public object
and registry diffs. It checks the owner commitment, QMDB state root and complete
sync target against each certified block before publication. A durable redb intent
is written before QMDB finalize; rows, history, current objects, transaction
locators and publication cursor then commit in one redb transaction. Restart
verifies the intent's certificate and publishes it only when QMDB's recovered root
matches. If QMDB still holds the preceding root, recovery drops the intent and
replays that block again. Any other root, gap or conflicting payload stops replay.

The stores have different responsibilities. Commonware's follower archive owns
finalized consensus history. Replay QMDB owns the certified current object and
owner trees: putting discovery keys into it would change the consensus root.
redb provides derived range indexes and one current object projection. Its
certification-evidence table retains one protobuf bundle per height so historical
openings/closings remain verifiable after their checkpoint is superseded; edge
and event rows hold transaction locators, not additional canonical transaction
copies. The latest cursor is a height reference into that table. Each read caches
at most one decoded block while resolving locators.

Rebuilding the derived index uses finalized history and fresh replay storage.

Index files and replay partitions are scoped by genesis, trust and schema. A new
scope builds from genesis/archive in a separate namespace; old data is retained.
This change also advances the on-disk index format to 3. Existing older-format files
are rejected with a rebuild instruction; use a new storage directory. Deploy the
indexer and Explorer schema-2 consumer together: prior cursors/response layouts
and schema-derived RPC method IDs are incompatible. No live storage is deleted.
redb holds a 64 MiB page cache. Queries retain a read transaction, so in-flight
readers keep their exact view during publication. The open lookup contains only
live edges; closing an edge removes its open lookup entries immediately. Closed
history does not slow open discovery. Separate party/kind prefixes avoid owner enumeration. At most 16
transport queries run concurrently; query replies have a two-second deadline,
list scans also have bounded visit/time budgets, and the selected response
representation is limited to 8 MiB without encoding the other representation.

The common `hellas_chain::edge_index` types, parser, cursor normalization and
shared projection checks compile for Wasm. Explorer uses these checks with its
existing `ExplorerVerifier`; there is no parallel client facade. They check independently
trusted block certificates, opening/closing inclusion, canonical terms and edge
identity, decoded object fields and registry bindings. It returns ordinary
reported-data types: discovery, current objects and completeness remain
**indexer-reported**. An opening certificate does not prove that its edge is still
open. Object membership and range proofs are not provided.

For deterministic integration fixtures, run:

```sh
HELLAS_EDGE_FIXTURE_DIR=/tmp/edge-fixtures cargo test -p hellas-chain \
  --no-default-features --features explorer-origin --lib native_edge_index
```

`basic/` and `work/` each contain independent `trust.json`, `genesis.json`, a
`manifest.json` route/payload map and paired JSON/protobuf responses. The work
fixtures execute Open, Start, Response, Adjudicated, bond Timeout and Freeze on
real QMDB roots and verify all nested evidence with the shared verifier. The tests
also cover pagination within a checkpoint, typed restart after publication, old in-flight
readers, gap/parent/root refusal, nonempty publication recovery on both sides of
QMDB finalize, and a large cold closed index. Fixture blocks are produced by the
validator execution path, independently of the observed replay adapter.
