# Integration regressions for recovery, accounting and source selection.
# These targets are intentionally explicit: --lib does not execute them, and
# the model upload case requires the models feature rather than work alone.
set -euo pipefail

cargo test --locked -p hellas-channel --test work_accept --test work_close --test work_store_channel
cargo test --locked -p hellas-authority --test http_usage
cargo test --locked -p hellas-client --features models --test work
cargo test --locked -p hellas-chain --no-default-features --features validator --lib reconciliation_evicts_never_includable_general_transactions
RUST_TEST_THREADS=1 cargo test --locked -p hellas-sdk --test native_execution paid_startup_selects_a_source_at_the_retained_journal_floor -- --exact
RUST_TEST_THREADS=1 cargo test --locked -p hellas-sdk --test native_execution a_paid_fetch_job_through_the_sdk_earns_the_price_and_returns_the_stake_separately -- --exact
