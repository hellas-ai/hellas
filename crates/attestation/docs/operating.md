# Operating attested confidential execution

How to run and connect to an Apple-App-Attest-attested provider. For *why* this
works and what it guarantees, see [`../README.md`](../README.md).

There are two roles: the **provider** (serves inference on a Mac) and the
**requester** (connects and sends prompts).

## Provider (macOS)

Attestation only works on a genuine, locked-down Apple machine.

1. **Build hardened.** Package, provision, and sign Hellas Gate using its
   [macOS signing guide](https://github.com/hellas-ai/gate/blob/52ade7b8be85835d8b43962463ff32913a638090/docs/SIGNING.md).
   Gate owns the app bundle, signing, and native App Attest producer because
   DeviceCheck is an app capability, not a portable protocol primitive.
   Run with SIP enabled and Full Security boot.
2. **Enroll (automatic).** The first time Gate starts its provider, it runs App
   Attest (`attestKey`) in the Secure Enclave and builds a
   `ProviderEnrollmentBundle` = signed genesis + the original Apple
   attestation object. Hellas core supplies only the generic `RootProver`
   interface and the portable verifier.
3. **Publish the pin.** The bundle's ContentId is the out-of-band trust anchor.
   Distribute it (and the bundle) to requesters through a channel you trust —
   this is the one thing that cannot be bootstrapped over the connection.
4. **Serve with Apple assurance:** start the sealed-Fetch provider from Gate.
   The command-line node intentionally no longer owns DeviceCheck enrollment
   or native proof production.

## Requester

Obtain the provider's enrollment-bundle ContentId (the pin) out of band, then:

```
hellas-cli \
  --assurance apple-app-attest \
  --provider-genesis <bundle-content-id-hex> \
  --apple-app-attest-app-id <teamID>.<bundleID> \
  --apple-app-attest-cdhashes <allowlisted build CDhashes> \
  llm ...            # or: fetch ...
```

| Flag | Meaning |
|---|---|
| `--assurance apple-app-attest` | Require an attested provider (default is `producer-signed`). |
| `--provider-genesis <content-id>` | The out-of-band pin. The provider's returned bundle must hash to this. |
| `--apple-app-attest-app-id <teamID.bundleID>` | The app identity. The RP-ID is `SHA256` of this; the assertion must match. |
| `--apple-app-attest-cdhashes <...>` | Allowlist of build CDhashes you trust not to leak. A build outside it is rejected. |
| `--retain` | Explicitly allow the provider to persist and publish prompt/token/transcript bytes (`llm`/`fetch`; default is ephemeral). Also expressible as OpenAI `store:true` in the body for `fetch`. |

Before any prompt byte leaves the requester, the client verifies, in order:
pin match → decode bundle → live peer == genesis transport key →
`register_apple` chain verification against the pinned Apple root + app id →
CDhash in the allowlist → open proof bound to this connection's QUIC exporter.
Any failure aborts before send.

## Graduation checklist (validate on real hardware)

1. Package + sign the app; confirm the entitlement denylist passes.
2. Create a fresh App Attest identity; publish the bundle; capture the pin.
3. From a second machine, connect with the pin + app-id + cdhashes; confirm the
   open gate blocks any prompt before verification completes.
4. Run one `llm` (Evaluate) and one `fetch`; confirm the returned result
   verifies.
5. Without `--retain`, confirm zero prompt-bearing files under the provider's
   data dir.
6. Restart the provider; confirm resume requires a fresh open verification.
7. Confirm a CDhash outside the allowlist is rejected at open.
8. Downgrade SIP / boot policy; confirm attestation fails and attested serving
   disables (the Secure Enclave key is invalidated).
