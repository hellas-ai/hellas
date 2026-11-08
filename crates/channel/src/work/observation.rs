//! Freshness of a continuously observed channel, by certified block time.
//!
//! One bound, [`MAX_CERTIFIED_AGE`], and one check of it,
//! [`check_certified_age`]. Admission asks it of the last read it
//! confirmed; a watcher asks it of every read it takes and refuses to act
//! on one that fails. Both durations here are derived from the kernel's
//! one response window, so a deployment cannot configure a watcher that
//! the window does not cover.

use super::EndpointError;
use hellas_auth::authority::UnixMillis;
use hellas_kernel::{MAX_BLOCK_TIME_LEAD_MS, RESPONSE_WINDOW_MS};
use std::time::Duration;
use tokio::time::Instant;

/// Longest a watcher waits between certified reads of its channels.
pub const POLL: Duration = Duration::from_millis(RESPONSE_WINDOW_MS / 16);

/// How often a provider reads while something it started on chain is
/// waiting to be seen: a setup's Open, a live contest, or a transaction it
/// just submitted. That is latency, not safety — the response window is
/// sized for [`POLL`] — so this only keeps those steps from waiting a
/// whole [`POLL`] each.
pub const SETUP_POLL: Duration = Duration::from_millis(RESPONSE_WINDOW_MS / 256);

/// Oldest a certified read may be — local time minus the block's own
/// timestamp — and still be acted on.
pub const MAX_CERTIFIED_AGE: Duration = Duration::from_millis(RESPONSE_WINDOW_MS / 8);

// The response window's safety argument. A start lands in a block
// stamped `t`; the answer is due before `t + RESPONSE_WINDOW_MS` of
// block time. Block time leads real time by at most the skew bound, so
// the deadline arrives no earlier than `RESPONSE_WINDOW_MS - lead` after
// the start in real time. A watcher notices within one poll plus one
// certified age, and at least half the window is then left to submit
// the answer and get it included, through leader timeouts.
const _: () = assert!(
    RESPONSE_WINDOW_MS / 16 + RESPONSE_WINDOW_MS / 8 + MAX_BLOCK_TIME_LEAD_MS
        <= RESPONSE_WINDOW_MS / 2,
    "the watcher's detection budget must leave half the response window for inclusion"
);

/// Refuses a certified read older than [`MAX_CERTIFIED_AGE`].
///
/// A block stamped ahead of local time is age zero: consensus bounds that
/// lead, and the window budgets it.
///
/// # Errors
///
/// [`EndpointError::ObservationStale`] when the read is too old or the
/// local clock is unreadable.
pub fn check_certified_age(certified_at_ms: u64) -> Result<Duration, EndpointError> {
    let now = UnixMillis::now().map_err(|_| EndpointError::ObservationStale)?;
    let age = Duration::from_millis(now.0.saturating_sub(certified_at_ms));
    if age < MAX_CERTIFIED_AGE {
        Ok(age)
    } else {
        Err(EndpointError::ObservationStale)
    }
}

/// When a read was confirmed, by both clocks. Counting host sleep through
/// the wall clock and refusing rollback through the monotonic one keeps a
/// confirmed read from looking younger than it is.
#[derive(Clone, Copy, Debug)]
struct Confirmed {
    certified_at_ms: u64,
    monotonic: Instant,
    wall: UnixMillis,
}

impl Confirmed {
    fn certified_at_ms_now(self) -> Option<u64> {
        let wall = UnixMillis::now().ok()?.0.checked_sub(self.wall.0)?;
        let elapsed = Duration::from_millis(wall).max(self.monotonic.elapsed());
        let elapsed = u64::try_from(elapsed.as_millis()).ok()?;
        // Shift the block's stamp back by the time since confirmation, so
        // the one check sees the age it has reached now.
        Some(self.certified_at_ms.saturating_sub(elapsed))
    }
}

/// A successful read only renews freshness when certified time advances.
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
    Fresh(Confirmed),
    Unavailable,
}

impl Observation {
    /// Confirms a read of the channel at `height`, stamped `certified_at_ms`.
    pub(super) fn confirm(
        &mut self,
        height: u64,
        certified_at_ms: u64,
    ) -> Result<(), EndpointError> {
        check_certified_age(certified_at_ms)?;
        let wall = UnixMillis::now().map_err(|_| EndpointError::ObservationStale)?;
        if self.height.is_none_or(|previous| height > previous) {
            self.height = Some(height);
            self.freshness = Freshness::Fresh(Confirmed {
                certified_at_ms,
                monotonic: Instant::now(),
                wall,
            });
        }
        self.check()
    }

    pub(super) fn remaining(&self) -> Option<Duration> {
        match self.freshness {
            Freshness::Fresh(confirmed) => Some(
                confirmed
                    .certified_at_ms_now()
                    .and_then(|at| check_certified_age(at).ok())
                    .map_or(Duration::ZERO, |age| MAX_CERTIFIED_AGE.saturating_sub(age)),
            ),
            _ => Some(Duration::ZERO),
        }
    }

    pub(super) fn check(&self) -> Result<(), EndpointError> {
        match self.freshness {
            Freshness::Fresh(confirmed) => confirmed
                .certified_at_ms_now()
                .ok_or(EndpointError::ObservationStale)
                .and_then(check_certified_age)
                .map(|_| ()),
            Freshness::Unavailable => Err(EndpointError::NotAdmitting),
            Freshness::Stale => Err(EndpointError::ObservationStale),
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

    fn now_ms() -> u64 {
        UnixMillis::now().unwrap().0
    }

    fn ms(duration: Duration) -> u64 {
        u64::try_from(duration.as_millis()).unwrap()
    }

    #[test]
    fn a_finalized_denial_survives_suspend_and_older_readiness() {
        let mut observation = Observation::default();
        observation.confirm(10, now_ms()).unwrap();
        observation.reject(20);
        observation.suspend();
        for height in [15, 20] {
            assert_eq!(
                observation.confirm(height, now_ms()),
                Err(EndpointError::NotAdmitting)
            );
        }
        observation.confirm(21, now_ms()).unwrap();
        assert!(observation.check().is_ok());
    }

    #[test]
    fn a_read_older_than_the_bound_is_refused_and_a_fresh_one_restores() {
        let mut observation = Observation::default();
        let stale = now_ms() - ms(MAX_CERTIFIED_AGE) - 1;
        assert_eq!(
            observation.confirm(1, stale),
            Err(EndpointError::ObservationStale)
        );
        assert_eq!(observation.check(), Err(EndpointError::ObservationStale));
        observation.confirm(2, now_ms()).unwrap();
        assert!(observation.check().is_ok());
    }

    #[test]
    fn a_confirmed_read_ages_out_on_the_same_bound() {
        let mut observation = Observation::default();
        let nearly = now_ms() - ms(MAX_CERTIFIED_AGE) + 50;
        observation.confirm(1, nearly).unwrap();
        // Confirmed 100 ms ago by both clocks: the age it has reached now
        // is past the bound.
        let Freshness::Fresh(confirmed) = &mut observation.freshness else {
            panic!("the read was confirmed");
        };
        confirmed.monotonic = Instant::now()
            .checked_sub(Duration::from_millis(100))
            .unwrap();
        confirmed.wall = UnixMillis(confirmed.wall.0 - 100);
        assert_eq!(observation.check(), Err(EndpointError::ObservationStale));
        assert_eq!(observation.remaining(), Some(Duration::ZERO));
    }

    #[test]
    fn a_block_stamped_ahead_of_local_time_is_fresh() {
        assert_eq!(
            check_certified_age(now_ms() + MAX_BLOCK_TIME_LEAD_MS),
            Ok(Duration::ZERO)
        );
    }

    #[test]
    fn the_watcher_durations_derive_from_the_window() {
        assert_eq!(ms(POLL) * 16, RESPONSE_WINDOW_MS);
        assert_eq!(ms(MAX_CERTIFIED_AGE) * 8, RESPONSE_WINDOW_MS);
        assert!(MAX_CERTIFIED_AGE < Duration::from_millis(RESPONSE_WINDOW_MS));
    }
}
