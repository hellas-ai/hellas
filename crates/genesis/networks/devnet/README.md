# Development network

`Chain::Devnet` uses the genesis, finality trust, genesis payload and public
faucet accounts in this directory. Its CLI name is `devnet`. `id.txt` contains
the full genesis network ID without a trailing newline; the registry invariant
checks it against genesis and trust.

Re-genesis replaces these data files. Trust binds the exact genesis bytes, and
faucet keys must control their genesis allocations. Local tests use independent
synthetic profiles.
