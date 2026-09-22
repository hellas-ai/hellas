# `hellas-devnet-1`

This is the canonical development-only genesis document consumed by Hellas
validators, relays, indexers, and clients. It is not a released network and
must not hold anything of value.

The six validator identities are reproducible with validator seed `100`. The
two funded P-256 development accounts are reproducible from the following
public secret scalars:

| account | settlement key | secret scalar |
| --- | --- | --- |
| maker | `21tzoXVq7aGx61bNRTPDVn9hJhszdDA4CPcp9LYZL8ffT` | `0000000000000000000000000000000000000000000000000000000000000001` |
| taker | `236h7pukvqi6u8ADu53erbWyLYXNyNEuB9BRNMXtVKUfZ` | `0000000000000000000000000000000000000000000000000000000000000002` |

These credentials are intentionally public and unsafe for any production or
value-bearing deployment.

The foundation account `25uDmUCQcwYUHHyXthtEspGB2KVTmbys8vTSqAMXKNqRV`
has 1,000,000 development units for compute-provider stakes and gateway payment
channels. Its independently generated P-256 signing key is managed outside
this repository and is not one of the public development scalars above.
