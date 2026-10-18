//! Reject durable timestamps far ahead of the clock observed when opening this writer.
use super::NodeStoreError;
use hellas_auth::authority::UnixMillis;
use std::time::{Duration, Instant};

const MAX_FORWARD_SKEW_MS: u64 = 60_000;

pub(super) struct ClockBound {
    utc: UnixMillis,
    monotonic: Instant,
}
impl ClockBound {
    pub(super) fn new() -> Self {
        Self {
            utc: UnixMillis::now().unwrap_or_default(),
            monotonic: Instant::now(),
        }
    }
    pub(super) fn check(&self, now: UnixMillis) -> Result<(), NodeStoreError> {
        check(self.utc, self.monotonic.elapsed(), now)
    }
}
fn check(initial: UnixMillis, elapsed: Duration, now: UnixMillis) -> Result<(), NodeStoreError> {
    let elapsed = elapsed.as_millis().min(u128::from(u64::MAX)) as u64;
    let latest = initial
        .0
        .saturating_add(elapsed)
        .saturating_add(MAX_FORWARD_SKEW_MS);
    if now.0 > latest {
        return Err(NodeStoreError::ClockJump);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_bound_allows_small_skew_and_saturates_safely() {
        let initial = UnixMillis(1_000_000);
        let elapsed = Duration::from_secs(30);
        let actual = UnixMillis(initial.0 + 30_000);
        assert!(matches!(
            check(initial, elapsed, UnixMillis(u64::MAX)),
            Err(NodeStoreError::ClockJump)
        ));
        assert!(check(initial, elapsed, UnixMillis(actual.0 + MAX_FORWARD_SKEW_MS)).is_ok());
        assert!(
            check(
                initial,
                elapsed,
                UnixMillis(actual.0 + MAX_FORWARD_SKEW_MS + 1)
            )
            .is_err()
        );
        assert!(check(initial, elapsed, actual).is_ok());
        assert!(check(initial, elapsed, UnixMillis(1)).is_ok());
        assert!(check(UnixMillis(u64::MAX), Duration::MAX, UnixMillis(u64::MAX)).is_ok());
    }
}
