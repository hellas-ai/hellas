# `hellas-devnet-1`

This is the canonical development-only genesis document consumed by Hellas
validators, relays, indexers, and clients. It is not a released network and
must not hold anything of value.

The six validator identities are reproducible with validator seed `100`. The
maker and taker P-256 development accounts are reproducible from the following
public secret scalars:

| account | settlement key | secret scalar |
| --- | --- | --- |
| maker | `21tzoXVq7aGx61bNRTPDVn9hJhszdDA4CPcp9LYZL8ffT` | `0000000000000000000000000000000000000000000000000000000000000001` |
| taker | `236h7pukvqi6u8ADu53erbWyLYXNyNEuB9BRNMXtVKUfZ` | `0000000000000000000000000000000000000000000000000000000000000002` |

These credentials are intentionally public and unsafe for any production or
value-bearing deployment.

The 100 P-256 faucet accounts in [faucet.json](faucet.json), indexed `0` through
`99`, each have **931,145 credits** in genesis. Each row publishes the account's
index, base58 settlement address, and hexadecimal secret scalar. These
credentials are also intentionally public and unsafe for any production or
value-bearing deployment. Anyone can spend them; account selection does not
reserve an account or replenish its balance.

For index `N`, the 32-byte secret scalar is
`SHA256(b"hellas-devnet-1/faucet/v1\0" || N.to_be_bytes())`, where `N` is an
unsigned 32-bit integer and the domain ends in one zero byte. Interpret the
digest as a big-endian P-256 scalar. All 100 digests are valid nonzero P-256
scalars. The address is base58 of the 33-byte compressed SEC1 public key.
For example, the scalar of account 7 can be reproduced with:

```sh
python3 -c 'import hashlib; print(hashlib.sha256(b"hellas-devnet-1/faucet/v1\0" + (7).to_bytes(4, "big")).hexdigest())'
```

The CLI's global `--faucet` selects one random account for that invocation;
`--faucet-account N` selects a particular one. Both print the selected index
and settlement address to stderr and supply the existing software passkey
authenticator. They cannot be combined with each other or `--passkey`.
For example:

```sh
hellas contact export --faucet-account 7 --display-name "Public devnet user"
hellas serve --faucet
```

The account is the P-256 owner, separate from a node's secp256k1 signing key.
`chain delegate --faucet-account N` can authorize its coins for that node;
select the same `N` for provisioning and the paid-work client. Selecting a
passkey alone does not create a bond or a payment channel.

Changing this genesis requires a devnet re-genesis: its digest is part of the
consensus namespace. Existing chain state and trust documents must be
regenerated from the new document.

The foundation account `25uDmUCQcwYUHHyXthtEspGB2KVTmbys8vTSqAMXKNqRV`
has 1,000,000 development units for compute-provider stakes and gateway payment
channels. Its independently generated P-256 signing key is managed outside
this repository and is not one of the public development scalars above.
