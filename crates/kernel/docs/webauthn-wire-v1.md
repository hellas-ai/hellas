# Kernel WebAuthn signing envelope v1

This document pins the consensus wire contract implemented by
`verify_webauthn_assertion`. It describes the portable P-256 authorization
envelope used by kernel `Open` and mutual `Close` transactions; it is not a
general browser WebAuthn policy.

## Assertion and signed-data layout

A canonical `WebAuthnAssertion` is encoded as follows. Integers are unsigned
big-endian and every offset is in bytes.

| Offset | Length | Field |
|---:|---:|---|
| 0 | 1 | canonical format version `0x01` |
| 1 | 1 | `WebAuthnAssertion` type tag `0x09` |
| 2 | 32 | compact P-256 signature `r` |
| 34 | 32 | compact P-256 signature `s` |
| 66 | 32 | P-256 public x-coordinate |
| 98 | 32 | P-256 public y-coordinate |
| 130 | 8 | length of the bounded `webauthn_data` list |
| 138 | variable | `webauthn_data` bytes, at most 2,048 |

Inside an `Auth::WebAuthn`, this assertion follows the `Auth` envelope
`01 0a 01` (format, `Auth` type, WebAuthn variant).

`webauthn_data` is `authenticatorData || clientDataJSON`. WebAuthn defines
authenticator data as at least 37 bytes. Kernel v1 has no separate inner
length: it fixes the boundary after the first 37 bytes, so conforming v1
signers emit exactly the base 37-byte form before JSON. Bytes 0–31 are the
`rpIdHash`, byte 32 is the flags byte, and bytes 33–36 are the signature
counter. The verifier signs all 37 bytes but deliberately does not interpret
the `rpIdHash` or counter. The total bounded payload must fit 2,048 bytes.

The flags policy is:

- at least one of `UP` (`0x01`) or `UV` (`0x04`) must be set;
- `AT` (`0x40`) is rejected as `AttestedCredentialDataUnsupported`;
- `ED` (`0x80`) is rejected as `ExtensionsUnsupported`.

## Challenge and client-data grammar

The challenge is the unpadded base64url encoding of the complete 32-byte
canonical payload hash. It is exactly 43 ASCII characters using `A-Z`, `a-z`,
`0-9`, `-`, and `_`, with no `=` padding. An open signs `Tx::open_hash`; a
cooperative close signs `Tx::payload_hash` with `CloseKind::Mutual`.

Both hashes commit to the `NetworkId` the operation settles on, so the
same open on two networks produces two different challenges and an
assertion made for one is not a valid assertion on the other. A signer
that does not know its network cannot construct the challenge, which is
the intent: the network is a runtime input, never a compiled-in
constant.

`clientDataJSON` must be one complete top-level object, with optional JSON
whitespace and no trailing bytes. Member order is unrestricted. It must contain
exactly one literal, unescaped `"type"` member whose unescaped string value is
exactly `"webauthn.get"`, and exactly one literal, unescaped `"challenge"`
member whose unescaped string value is the 43-byte challenge. Escapes in either
required name or required value do not alias the required literal. Duplicate
literal `type` or `challenge` members are rejected.

Unknown members are tolerated because browsers add client-data fields over
time, but their values must be simple: a string with valid JSON escapes,
`true`, `false`, `null`, or a non-empty number token composed of digits and
`- + . e E`. Unknown objects and arrays are rejected, including nested-field
injection attempts. The number token is skipped rather than interpreted; v1
does not claim full JSON-number validation.

## Signature and party binding

The signed prehash is:

```text
SHA-256(authenticatorData || SHA-256(clientDataJSON))
```

The verifier reconstructs an uncompressed P-256 point from `0x04 || x || y`,
requires it to be a valid curve point, and derives the kernel party key as that
point's compressed SEC1 encoding. This 33-byte key must exactly equal the party
key committed by the transaction. The compact `r || s` signature verifies over
the prehash above, and `s` must be at or below the P-256 half-order; high-s
signatures are rejected even if mathematically valid.

## Deliberately portable

Kernel v1 does **not** enforce `origin`, does **not** bind or validate
`rpIdHash`, and accepts either UP or UV. Those bytes remain signature-bound,
but they are not authorization policy. This makes the assertion a portable
P-256 signing envelope for kernel payload hashes.

The policy itself lives in the `hellas-webauthn` crate, which every Hellas
verifier shares.
