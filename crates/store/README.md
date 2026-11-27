# `hellas-store`

Scoped, Xet-addressed objects and immutable trees, with pins controlling
visibility and retention. Memory and Disk share one core; Remote uses the same
Content protocol. An object's identity includes its content ID and exact byte
length. Network acquisition verifies both before atomically publishing its pin.

## Configuration

Pass a declaration to `serve --content-config content.toml`:

```toml
[content]
upper = "/var/lib/hellas/content-store"
lower = ["/srv/models", "/srv/huggingface/hub"]
index = "require"

# Replace these identity/length values with the output of store index.
[content.pins."config/whisper-weights"]
expect = "ee7d1129ce06b7939d6fb172c12501a71378c51301ff8700012e76d48dd0e1fc"
bytes = 75521280
```

Prepare the private derived index as the daemon's user before startup:

```sh
hellas store --content-config content.toml index
```

Local lower files stay in place. Walks exclude cache debris and symlinks; indexing refuses FIFOs and devices. Require mode refuses missing or stale records without hashing.
Resume mode hashes changed identities; `index --recheck` forces verification.
The owner-only index lives at `upper/fastresume.bin`. It caches verified work;
trusted file identity and the opened descriptor still determine validity.
Keep the upper and its ancestors private and stable. Lower files are assumed
immutable: an independent writer holding the same inode can change its bytes.

The upper defaults to `<home>/store` (`--home` or `HELLAS_HOME` selects home) and takes the node durability; capacity defaults to available
physical free space. Admission collects unpinned cache on demand; network-on-miss is refused by default.
Declared pins must live under `config/` and default to `Jobs`. They can explicitly
select `owner`, `jobs`, `granted` or `public`; Channel policy uses
`policy = { channel = "ID" }`. A job reads only its
declared closure through Jobs or its own Channel pins. Public visibility alone
does not grant job access. Config owns the targets and policies of `config/*` pins; every apply restores their declared values.

HF files using legacy (pre-2026) Xet chunking are refused; content identity stays canonical CDC.

Immutable HF declarations use `hf://org/repo@COMMIT_SHA`. Object declarations
can use `url`, optional HF `path`, `expect`, `bytes`, HTTPS `sha256`, and
`policy`. HTTPS declarations require both `expect` and the exact `bytes`
length; CLI HTTPS acquisition also permits a length without `expect`. With
no URL, `expect` and `bytes` together name a local object. HF credentials come from `HF_TOKEN` or the node user's HF token
file and are sent only to HF HTTPS origins. Downloads stream on blocking
workers with bounded reservations and the existing read/idle timeouts.

## Owner commands

The normal mode is authenticated daemon RPC using an existing Owner profile:

```sh
hellas store --profile owner-profile.json stat config/whisper-weights
hellas store --profile owner-profile.json read config/whisper-weights --start 0 --end 64 --out prefix.bin
hellas store --profile owner-profile.json pin ls
hellas store --profile owner-profile.json collect
```

Without a profile, commands use a checked local upper and may take
`--content-config`. They refuse a store ever opened by paid Work/Channel
scopes, even after its pins are removed: use the daemon. Connection or
authentication failures never fall back locally. Local-grant defaults to its
own authority-local upper. `index` remains local and only writes derived
index metadata, so it can prepare lowers while the daemon owns the store.

Both `resolve` and `acquire` lock a mutable Hub ref to one commit. Resolve
prints the commit and roots the repository tree without downloading weights.
Acquire fetches the selected repository, directory or file and prints its
content ID, commit and root names. It accepts `hf://ORG/REPO[@ref][/path]` and
Hugging Face repository, `tree`, `resolve` and `blob` URLs. Encode slashes in
refs as `%2F`. A missing ref follows the repository’s default branch.

```sh
hellas store --profile owner-profile.json resolve hf://org/repo
hellas store --profile owner-profile.json acquire https://huggingface.co/org/repo/tree/release
hellas store --profile owner-profile.json acquire hf://org/repo@release/model.bin --pin model
hellas store --profile owner-profile.json acquire https://example.org/model
hellas store --profile owner-profile.json acquire hellas://CONTENT_ID?seed=NODE_ID
hellas store --profile owner-profile.json pin set alias CONTENT_ID --bytes EXACT_BYTES --policy jobs
hellas store --profile owner-profile.json pin rm alias
```

A pin is a named garbage-collection root with a visibility policy. Acquire
roots a repository at `hf/ORG/REPO@SHA`, a Hub file or directory under that
name followed by its path, and other sources at `https/CONTENT_ID` or
`peer/CONTENT_ID`. `--pin NAME` adds an alias. Both roots use `--policy`,
which defaults to `owner`. Pin mutations use fresh compare-and-swap
metadata. `stat` and `read` accept `--path` within a tree; reads support byte
ranges, and pin listing uses protocol pagination. HTTPS uses the response
length when available; supply `--bytes` if the server omits it. A peer URI
identifies a node, and `--source-pin` selects its public content root. Owner
operations require the authenticated control carrier.

## Verification

The shared core conformance suite runs against Memory, Disk and RPC. Tests
exercise bounded chunk pages, tree traversal, scope expiry/revocation, exact
reservations, private staging/publication, lower file replacement, recovery
barriers and retained pins. HF tests cover independent Xet vectors, compressed
chunk framing, multi-term reconstruction, overfetch and offsets, hostile token
and range responses, and real immutable acquisition. The network test is
explicitly ignored by default:

```sh
cargo test -p hellas-store --test fetch fetches_the_reference_file_and_verifies_it -- --ignored --exact
```

HF HTTP uses `ureq` on blocking workers; streaming payloads are not materialized
as whole files in RAM. Both store and async application HTTP trust bundled
Mozilla roots, so trust does not depend on the host's certificate store.
