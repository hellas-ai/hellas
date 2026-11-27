# hellas-attestation

Provenance and confidentiality for Hellas execution. This crate answers one
question for a requester who sends a prompt to a provider on a machine they do
**not** control:

> How do I know the operator of that machine cannot read my prompt — without
> having to trust the operator at all?

## Attestation is not the state channel

Hellas has two separate concerns that are easy to conflate:

- **The state channel** (`open → work → close`, in `hellas-kernel`) is the
  **economic** layer: escrow funds, do work off-chain, settle up. It answers
  *"who pays whom, and how do we agree on the final tally?"*
- **Attestation** (this crate) is the **confidentiality** layer. It answers
  *"before I send my secret prompt, how do I know this box is a genuine,
  locked-down Apple machine whose operator can't read it?"*

They compose but never overlap. Attestation is a **gate in front of the work**,
not a change to settlement. Think of the state channel as the contract for a
deal, and attestation as checking the vault is real and sealed before you put
your document in it.

## The three phases

### 1. Enrollment — once per provider

The provider's Mac app asks Apple to vouch for it.

```
 Provider Mac app                      Apple
     │                                   │
     │  generateKey  ───────────────────▶│   a key is born inside the Secure
     │                                   │   Enclave (non-extractable)
     │  attestKey    ───────────────────▶│
     │◀── attestation object ────────────│   Apple signs: "this key lives in a
     │                                       genuine Secure Enclave, in the app
     │                                       whose CDhash is X"
     │
     │  bundle = { identity(transport key, producer key),
     │             Apple attestation object }
     │  publish bundle;   pin = ContentId(bundle)
     │
     └╌╌╌ requesters obtain `pin` out-of-band ╌╌╌▶
```

The `pin` is a small content hash. It is the **out-of-band trust anchor**: a
requester must already know it, because anything delivered *over* the
connection could be forged by a man-in-the-middle. No in-band mechanism can
bootstrap this — the anchor has to come from outside the channel.

### 2. Confidential open — every connection (the gate)

```
 Requester (has pin)                         Provider (attested Mac)
     │                                            │
     │════ QUIC connect (encrypted channel) ═════▶│
     │──── OpenRequest { nonce } ────────────────▶│
     │                                            │  Secure Enclave signs an
     │                                            │  assertion over {connection
     │◀─── OpenResponse { bundle, assertion } ────│  exporter, nonce, keys, …}
     │                                            │
     │  CHECK, before sending any prompt byte:    │
     │   1. hash(bundle) == pin ................. right provider, not a MITM
     │   2. register_apple(attestation) ......... APPLE vouches for the SE key
     │   3. live peer == bundle transport key ... not a relay in the middle
     │   4. app ID and optional CDHash pins ..... the requester's Apple policy
     │   5. assertion binds THIS connection ..... live & fresh, not replayed
     │                                            │
     │  ✅ all pass → trust established           │
     │──── prompt / request (the "work") ────────▶│  executes locally, in RAM;
     │◀─── signed result ────────────────────────│  no disk, no logs, no leak
```

If any line fails, the requester **aborts and never sends the prompt.**

### 3. Work

The prompt flows and Evaluate/Fetch runs as usual — now inside a process the
requester has cryptographically verified. Settlement (`open → work → close` in
the kernel) runs on its own track.

## How this secures the user

Each link is verified **at open, before the prompt leaves the requester**:

1. **Apple vouches for the hardware.** `register_apple` walks Apple's
   certificate chain: this key lives in a real Secure Enclave on a genuine,
   un-jailbroken Apple device. Apple will not sign that for an emulator or a
   tampered machine.
2. **The app matches your policy.** The default accepts any build of
   `2F53L9ZR3N.ai.hellas.gate`. You can replace that app ID and supply
   exact CDHashes to accept only builds you reviewed.
3. **The platform cannot be pried open.** For the attestation to exist and the
   key to function, the machine runs with SIP on, hardened runtime, and — 
   enforced at packaging — no debugger/injection entitlements. So the operator,
   *even as root*, cannot attach a debugger or dump process memory.
4. **This exact connection lands inside that attested process.** The proof is
   bound to the live QUIC keying-material exporter. A relay/proxy sees a
   different exporter and cannot forge the proof.
5. **Verify-before-send.** All of the above is checked first; nothing secret
   moves until every link holds.

**Net guarantee:** a requester can send a prompt to a machine they do not
control and be cryptographically confident the operator cannot read it —
without trusting the operator. Trust roots in Apple plus the hardware/platform,
not in anyone's promise.

## Settlement: attestation stays OFF consensus (deliberately)

Attestation never touches the chain, and this is a decision, not an omission.

The chain's job is the **state channel**: it binds *"key A opened an edge with
key K and both signed these payouts."* It is agnostic about **why** A chose K.
Attestation is precisely how A *chose* K — an **off-chain admission gate** the
requester runs (the open handshake above) *before* deciding to open a channel.
If a provider cannot prove it is a genuine attested enclave, the requester
simply does not open the channel and finds another operator. The two layers
compose without overlapping — exactly the orthogonality this document opened
with.

Why nothing on-chain is needed, case by case:

- **Payment for work (Evaluate/Fetch):** the cumulative amount the client
  signs. A dispute is an ordinary economic close (`Freeze`, or the staged
  close contest). True of every channel; no Apple input.
- **"Prove you're attested to get paid":** the requester already demanded that
  proof *before opening*. A provider that couldn't prove it never got a
  channel. Nothing is left to adjudicate on-chain.
- **"You leaked my prompt":** confidentiality is a negative — not observable or
  provable on-chain under any design. Prevented by verify-before-send, not by
  consensus.

So there is **no attested `ProtocolCode`, no seal verifier for Apple, no
preverified cache, no on-chain certificate parsing, and no ZK proof of the
Apple chain.** The kernel has no external verifier seam at all, and settles
ordinary bilateral channels between ordinary keys.

### The one wiring requirement

The attested identity must bind the provider's **settlement key** (the kernel
`Key` used as an edge party), alongside the transport and producer keys it
already binds (`crates/rpc/src/protocol/identity.rs`). Otherwise a provider
could attest one key and settle with another. With the settlement key in the
bundle, the requester opens the edge with a key its open handshake has proven
belongs to the attested enclave — and the chain needs to know nothing more.

### The only future trigger to revisit this

On-chain attestation evidence becomes necessary *only* if some party who is
**not one of the two channel participants** needs on-chain-verifiable proof
that work was attested — e.g. a protocol-level reward that pays providers for
doing attested execution, adjudicated by third parties. No Evaluate/Fetch flow
needs this. If it ever arrives, it is its own feature (a designated-verifier or
ZK-backed registration of the attested key), added then — it does not shape the
core now.

## Honest limits

- It does **not** defend against Apple itself, a kernel/hardware zero-day, or a
  build you *wrongly* allowlisted.
- It proves **confidentiality** (the operator cannot read your prompt), **not
  correctness** (nothing here says the model computed the right answer).

## Key entry points

- `register_apple` — verify an Apple attestation object against the pinned root
  CA; produce a chain-verified `RegisteredAppleCredential` with its RP-ID hash.
- `ApplePolicy` — the requester's accepted app IDs (RP-ID =
  `SHA256(teamID.bundleID)`, Gate by default) and optional CDHash pins;
  `register` and `verify_assertion` apply it.
- `AssertionCounterStore` — injected port for per-key monotonic counter
  high-water marks (the filesystem impl lives in the caller).
- The confidential open handshake lives in `hellas-rpc` (`open`,
  `open_proof_binding`) and `hellas-client` (the requester-side gate).
