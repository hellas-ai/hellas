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
3. **Publish the offer.** Paid offers carry the enrollment and signed bond
   proposal, bound together by the provider's settlement key. Grant Offers
   carry the enrollment with the grant. Clients check the enrollment and apply
   their Apple policy before sending work.
4. **Serve with Apple assurance:** start the sealed-Fetch provider from Gate.
   The command-line node does not own DeviceCheck enrollment or native proof
   production.

## Requester

Buy an Apple-attested HTTPS Fetch with `hellas fetch`:

```sh
hellas fetch https://api.example.com/v1/models --contract http \
  --assurance apple-app-attest --pay 20 --provider ENROLLMENT_ID@NODE_ID
```

The assurance flag requires a Secure Enclave provider. Apple providers must
match the caller's Apple policy at either assurance level. That policy
accepts any build of `2F53L9ZR3N.ai.hellas.gate` by default. Add repeatable
`--require-apple-app-id` flags to replace the Gate ID, and repeat
`--require-apple-cdhash` to limit acceptance to exact builds. Assertion
counters persist in the caller's Hellas home.

Paid Fetch journals contain accounting metadata and omit request and response
bodies. See the [paid work guide](../../../docs/paid-gateway.md) for funding
and daemon backend settings.

Before any prompt byte leaves the requester, the client verifies, in order:
pin match → decode bundle → live peer == genesis transport key →
`register_apple` chain verification against the pinned Apple root + app id →
match any configured CDHash pins → open proof bound to this connection's QUIC exporter.
Any failure aborts before send.

## Graduation checklist (validate on real hardware)

1. Package + sign the app; confirm the entitlement denylist passes.
2. Create a fresh App Attest identity; publish the bundle; capture the pin.
3. From a second machine, connect with the provider address and
   `--assurance apple-app-attest`. Confirm verification completes before any
   prompt is sent.
4. Send a request through the paid HTTPS gateway; confirm the returned
   transcript verifies and its payment is acknowledged.
5. With `--zdr`, confirm no payload archive is created and no request/response
   body is present in either Fetch journal.
6. Restart the provider; confirm resume requires a fresh open verification.
7. Set a CDHash pin for a different build and confirm verification rejects the provider.
8. Downgrade SIP / boot policy; confirm attestation fails and attested serving
   disables (the Secure Enclave key is invalidated).
