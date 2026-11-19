# Compiled network

This directory supplies the binary's one network: genesis, finality trust,
public faucet accounts and validator transport routes. Replace these files
for a re-genesis; source and tests do not name a network generation.

Trust binds the exact genesis bytes. Faucet keys must control their genesis
allocations. Routes provide transport, not trust. Local tests may supply an
independent profile with `--chain-config FILE`.
