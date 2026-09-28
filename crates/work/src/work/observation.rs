//! Process-local freshness of a continuously observed channel.

use super::EndpointError;
use std::time::{Duration, SystemTime};
use tokio::time::Instant;

/// Capture before reading the chain. Using both clocks counts host sleep even
/// where monotonic time excludes it, and fails closed on wall-clock rollback.
#[derive(Clone, Copy, Debug)]
pub struct ObservationTime {
    monotonic: Instant,
    wall: SystemTime,
}

impl ObservationTime {
    /// Marks the beginning of a chain observation.
    #[must_use]
    pub fn now() -> Self {
        Self {
            monotonic: Instant::now(),
            wall: SystemTime::now(),
        }
    }

    fn elapsed(self) -> Option<Duration> {
        self.wall
            .elapsed()
            .ok()
            .map(|wall| wall.max(self.monotonic.elapsed()))
    }
}

/// A successful read only renews freshness when finalized history advances.
/// Reading an old tip repeatedly cannot keep a disconnected channel admitting.
#[derive(Debug, Default)]
pub(super) struct Observation {
    height: Option<u64>,
    confirmed: Option<(ObservationTime, Duration)>,
}

impl Observation {
    pub(super) fn confirm(&mut self, height: u64, started: ObservationTime, max_age: Duration) {
        if self.height.is_none_or(|previous| height > previous) {
            self.height = Some(height);
            self.confirmed = Some((started, max_age));
        }
    }

    pub(super) fn check(&self) -> Result<(), EndpointError> {
        if self
            .confirmed
            .is_some_and(|(started, max_age)| started.elapsed().is_some_and(|age| age < max_age))
        {
            Ok(())
        } else {
            Err(EndpointError::ObservationStale)
        }
    }

    pub(super) fn suspend(&mut self) {
        self.confirmed = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_sleep_and_clock_rollback_cannot_extend_readiness() {
        for wall in [
            SystemTime::now() - Duration::from_secs(60),
            SystemTime::now() + Duration::from_secs(60),
        ] {
            let mut observation = Observation::default();
            observation.confirm(
                1,
                ObservationTime {
                    monotonic: Instant::now(),
                    wall,
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
