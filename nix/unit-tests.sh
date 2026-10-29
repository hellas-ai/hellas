# Library and CLI command tests, excluding the chain's live-node suite and
# the four SDK scenarios that start a validator network, and full model
# compilation. Release checks run these through check-chain-setup,
# check-validator, check-sdk-paid-work and check-model-programs.
cargo test --locked --workspace --exclude hellas-chain --exclude hellas-kernel --lib --bins -- \
  --skip client_owner::tests::durable_funding_retries_one_signature_and_reserves_other_providers \
  --skip client_owner::tests::competing_owner_spend_releases_conflicted_inputs_for_another_provider \
  --skip paid_gateway::tests::retained_gateway_policy_waits_for_chain_recovery_and_has_a_deadline \
  --skip paid_gateway::connection_tests::an_unresponsive_paid_quote_yields_to_the_next_provider_within_the_connection_bound \
  --skip model::package::tests::shipped_qwen3_program_matches_catena_models \
  --skip model::whisper::tests::shipped_whisper_program_matches_catena_models \
  --skip model::flux::tests::shipped_flux_program_matches_catena_models

# Keep chain codecs and proof verification without starting indexers or validators.
cargo test --locked -p hellas-chain --no-default-features --features client,proof-verify,work-watcher --lib

# These tests live in tests/ but exercise the pure kernel and canonical payment
# encodings. Directory placement must not exclude them from the merge checks.
cargo test --locked -p hellas-kernel --all-features
cargo test --locked -p hellas-channel --test paid_fetch_vectors --test paid_work_vectors --test work_funding_vectors
