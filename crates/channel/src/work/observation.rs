//! Process-local freshness of a continuously observed channel.

use super::EndpointError;
use hellas_auth::authority::UnixMillis;
use std::time::Duration;
use tokio::time::Instant;

/// Capture before reading the chain. Using both clocks counts host sleep even
/// where monotonic time excludes it, and fails closed on wall-clock rollback.
#[derive(Clone, Copy, Debug)]
pub struct ObservationTime {
    monotonic: Instant,
    wall: Option<UnixMillis>,
}

impl ObservationTime {
    /// Marks the beginning of a chain observation.
    #[must_use]
    pub fn now() -> Self {
        Self {
            monotonic: Instant::now(),
            wall: UnixMillis::now().ok(),
        }
    }

    fn elapsed(self) -> Option<Duration> {
        let elapsed = UnixMillis::now().ok()?.0.checked_sub(self.wall?.0)?;
        Some(Duration::from_millis(elapsed).max(self.monotonic.elapsed()))
    }
}

/// A successful read only renews freshness when finalized history advances.
/// Reading an old tip repeatedly cannot keep a disconnected channel admitting.
#[derive(Debug, Default)]
pub(super) struct Observation {
    height: Option<u64>,
    freshness: Freshness,
}

#[derive(Debug, Default)]
enum Freshness {
    #[default]
    Stale,
    Fresh(ObservationTime, Duration),
    Unavailable,
}

impl Observation {
    pub(super) fn confirm(&mut self, height: u64, started: ObservationTime, max_age: Duration) {
        if self.height.is_none_or(|previous| height > previous) {
            self.height = Some(height);
            self.freshness = Freshness::Fresh(started, max_age);
        }
    }

    pub(super) fn check(&self) -> Result<(), EndpointError> {
        match self.freshness {
            Freshness::Fresh(started, max_age)
                if started.elapsed().is_some_and(|age| age < max_age) =>
            {
                Ok(())
            }
            Freshness::Unavailable => Err(EndpointError::NotAdmitting),
            _ => Err(EndpointError::ObservationStale),
        }
    }

    pub(super) fn suspend(&mut self) {
        if !matches!(self.freshness, Freshness::Unavailable) {
            self.freshness = Freshness::Stale;
        }
    }

    pub(super) fn reject(&mut self, height: u64) {
        self.height = Some(self.height.map_or(height, |previous| previous.max(height)));
        self.freshness = Freshness::Unavailable;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_finalized_denial_survives_suspend_and_older_readiness() {
        let mut observation = Observation::default();
        let age = Duration::from_secs(5);
        observation.confirm(10, ObservationTime::now(), age);
        observation.reject(20);
        observation.suspend();
        for height in [15, 20] {
            observation.confirm(height, ObservationTime::now(), age);
            assert_eq!(observation.check(), Err(EndpointError::NotAdmitting));
        }
        observation.confirm(21, ObservationTime::now(), age);
        assert!(observation.check().is_ok());
    }

    #[test]
    fn an_unreadable_clock_cannot_establish_freshness() {
        let mut observation = Observation::default();
        observation.confirm(
            1,
            ObservationTime {
                monotonic: Instant::now(),
                wall: None,
            },
            Duration::from_secs(5),
        );
        assert_eq!(observation.check(), Err(EndpointError::ObservationStale));
    }

    #[test]
    fn host_sleep_and_clock_rollback_cannot_extend_readiness() {
        let now = UnixMillis::now().unwrap();
        for wall in [UnixMillis(now.0 - 60_000), UnixMillis(now.0 + 60_000)] {
            let mut observation = Observation::default();
            observation.confirm(
                1,
                ObservationTime {
                    monotonic: Instant::now(),
                    wall: Some(wall),
                },
                Duration::from_secs(5),
            );
            assert_eq!(observation.check(), Err(EndpointError::ObservationStale));
            observation.confirm(2, ObservationTime::now(), Duration::from_secs(5));
            assert!(
                observation.check().is_ok(),
                "new finalized progress restores readiness"
            );
        }
    }
}
