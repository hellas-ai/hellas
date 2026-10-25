# `hellas-store`

A content store addressed by **Xet file hash** — the same hash
HuggingFace uses.

That single choice is what the design turns on: **an existing
HuggingFace cache is already a populated store.** Adopting one is
indexing, not downloading.

## The shape

A Nix store, or a BitTorrent client's view of its own disk. An entry is
named by a hash of its content, so where it came from is not part of its
identity — which is what makes substitution sound rather than merely
convenient. Any source producing the right bytes is as good as any
other.

| BitTorrent | here |
| --- | --- |
| infohash | Xet file hash |
| metainfo / `.torrent` | the chunk list |
| piece + piece hash | chunk + `DATA_KEY`-keyed chunk hash |
| HTTP seed | HuggingFace, ModelScope |
| peers | other nodes *(not built)* |
| fastresume | `fastresume::Records` |

## Using it

```
hellas store adopt                 # index the HuggingFace cache in place
hellas store adopt --cache PATH    # or a specific one
hellas store status                # what is remembered
hellas store fetch --id <64 hex> --repo org/name --out PATH
```

`adopt` is a read, not a copy: the store points at the files where they
already lie. Cost is one read per blob. Later scans and restarts reuse
hashes while the file identity remains unchanged and the persisted index
stays inside the user-private state boundary.

## Persisting hashing work

`adopt` writes `fastresume.bin` under `$HOME/.hellas/store` — or
`$HELLAS_STORE_DIR`, and never inside the HuggingFace cache, which is not
ours. The record contains the file identity, content id, and chunk list
from earlier hashing work, so a later run can skip unchanged files.

The record is a cache of work, not a registry of cache roots and not a
source of truth. It is trusted private state: loading requires an ordinary
file owned by the effective user with no group/other permissions, opened
without following a final symlink. Its parent must be owned by that user,
not a symlink, and not group/other writable. The parent and its ancestors
must remain stable and trusted. Non-private indexes are ignored, so their
files are re-hashed. Accepted records are still checked against the live
content file's identity before reuse.

## Indexing produces two things, and the second is the valuable one

`index` returns the content id **and the chunk list**. Keeping only the
id would discard the expensive half of a pass we have to make anyway.

The chunk list is the metainfo. A Xet file hash is a Merkle root over
exactly those descriptors, so holding them makes a later *partial* fetch
verifiable. This matters because **HuggingFace's reconstruction protocol
returns no chunk hashes at all** — content arriving from an untrusted
source is otherwise unverifiable until the whole file is reassembled,
which is a poor way to discover a peer is lying.

## Two rules that are not obvious

**Never trust an id you did not compute.** HuggingFace advertises an
`x-xet-hash` per file. For Xet-native uploads it is exactly the Xet hash
of the content; for legacy-LFS content bridged into Xet it is
measurably *not*, with sha256 confirming the bytes were the ones HF
meant. Ids in this store are ones we computed.

**`have` and `materialize` are different questions.** `have` is local,
cheap, and touches no network. `materialize` may spend bandwidth and
disk. The split is enforced by two traits: a `Substituter` answers where
content already is; only a `Fetcher` can make it appear.

## Verification

Three layers, deliberately:

1. Per chunk, when we hold a chunk list, as bytes arrive.
2. Whole file, against the id that was requested, before anything is
   written.
3. Re-indexed after writing — so a *fetcher* that lies cannot leave
   bytes in the store under a name they do not own.

## Conformance

The hashing is checked against the published Xet spec vectors, and the
xorb decoder against 50,469 bytes fetched from HuggingFace's own CAS.

Byte-grouping (scheme 2) is covered too, against a fixture from
`HuggingFaceTB/SmolLM2-135M` whose chunks are both scheme 2 and both a
ragged length — the case where an ungrouper that assumes equal groups
goes wrong. The oracle is not our own decoder: HuggingFace serves the
reconstructed plaintext for the same byte range, and our decoded chunks
must equal it.

Still not covered: multi-term and multi-xorb reconstructions, a non-zero
`offset_into_first_range`, and the HTTP layer itself.

## Why this crate uses `ureq` and not `reqwest`

The rule is:

> **Streaming or async-context HTTP uses `reqwest`. Synchronous,
> fully-buffered content fetch inside `hellas-store` uses `ureq`.**

The store API is synchronous and its HTTP responses are fully buffered.
`ureq` fits that interface without introducing `reqwest::blocking` and
its async-runtime constraints.

Both clients are configured with **bundled Mozilla roots**
(`rustls-webpki-roots` / `webpki-roots`) rather than the OS trust store.
Two clients in one binary trusting two different sets of certificate
authorities is a silent policy split, and "which roots did we trust when
we fetched this content" should have one answer — a reproducible one,
independent of what an admin or MDM installed on the host.

## Not built

Peer-to-peer. `Fetcher` is the seam it implements, and the chunk lists
the store already keeps are what will make a peer's partial response
verifiable — the property HuggingFace's protocol cannot provide. What it
needs is a wire protocol: announce what you hold, ask who has an id,
request chunk ranges.
