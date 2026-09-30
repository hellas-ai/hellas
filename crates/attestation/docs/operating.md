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
   carry the enrollment with the grant. A requester derives the bundle's pin
   from the verified offer and selects Apple app policy independently.
4. **Serve with Apple assurance:** start the sealed-Fetch provider from Gate.
   The command-line node intentionally no longer owns DeviceCheck enrollment
   or native proof production.

## Requester

Use the paid HTTPS Fetch gateway. Configure each pool entry's mandatory
`provider_genesis` with the signed paid offer or an independently obtained
ContentId pin. Select `apple_app_id` and `apple_cd_hashes` from trusted release
metadata. See the
[paid gateway guide](../../../docs/paid-gateway.md) for funding and pool fields,
and [HTTP routing](../../../docs/http-gateway.md) for exact route configuration.

```sh
hellas-cli gateway \
  --assurance apple-app-attest \
  --paid-work-config /srv/hellas/pool.json \
  --http-fetch-config /srv/hellas/http-routes.json \
  --zdr
```

`--zdr` disables gateway payload archives and requires a ZDR policy for every
HTTP request. Paid Fetch journals contain accounting metadata, never request
or response bodies. These storage rules do not establish an upstream API's
retention policy. Native token Work remains producer-signed; Apple assurance
here is the paid Fetch path. Owner and principal routes use grant-funded Work with the same provider authentication.

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
4. Send a request through the paid HTTPS gateway; confirm the returned
   transcript verifies and its payment is acknowledged.
5. With `--zdr`, confirm no payload archive is created and no request/response
   body is present in either Fetch journal.
6. Restart the provider; confirm resume requires a fresh open verification.
7. Confirm a CDhash outside the allowlist is rejected at open.
8. Downgrade SIP / boot policy; confirm attestation fails and attested serving
   disables (the Secure Enclave key is invalidated).
