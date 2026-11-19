# Compiled development network

`Network::Devnet` supplies these genesis, finality trust, genesis payload,
public faucet accounts and validator transport routes. Its CLI name is `devnet`;
its full network ID comes from genesis. Re-genesis replaces files here without
changing Hellas source or tests.

Trust binds the exact genesis bytes. Faucet keys must control their genesis
allocations. Routes provide transport, not trust. Local tests may supply an
independent profile with `--chain-config FILE`.
