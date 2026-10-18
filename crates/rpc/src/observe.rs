//! Timing events for paid-work operations under [`TARGET`].
//!
//! [`Timing`] reads the clock only when tracing enables the event. Samples
//! report durations and identifying fields; they do not drive protocol
//! decisions. [`Samples`] retains individual observations for inspection.

use hellas_auth::authority::UnixMillis;
use web_time::Instant;

/// Tracing target shared by all timing events.
pub const TARGET: &str = "hellas.mount.measure";

/// The level every sample is emitted at.
pub const LEVEL: tracing::Level = tracing::Level::DEBUG;

/// Start time, absent when tracing disables timing events.
#[derive(Clone, Copy, Debug)]
pub struct Timing(Option<Instant>);

impl Timing {
    /// Starts timing one piece of work, if a sample of it could reach
    /// anyone.
    #[must_use]
    pub fn start() -> Self {
        Self(tracing::enabled!(target: TARGET, LEVEL).then(Instant::now))
    }

    /// Elapsed milliseconds, or `None` if timing was disabled.
    #[must_use]
    pub fn ms(self) -> Option<f64> {
        self.0
            .map(|started| started.elapsed().as_secs_f64() * 1_000.0)
    }
}

/// One observation a seam emitted.
#[derive(Clone, Debug, PartialEq)]
pub struct Sample {
    /// Name of the measured operation.
    pub quantity: &'static str,
    /// How long the work took.
    pub ms: f64,
    /// Collection time in Unix milliseconds, without clock-order correction.
    pub at_unix_ms: u64,
    /// The identity fields the seam carried, in emission order.
    pub fields: Vec<(&'static str, String)>,
}

impl Sample {
    /// Returns what the seam recorded under `name`.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find_map(|(field, value)| (*field == name).then_some(value.as_str()))
    }
}

/// Tracing subscriber retaining raw timing samples in emission order.
#[derive(Debug, Default)]
pub struct Samples(std::sync::Mutex<Vec<Sample>>);

impl Samples {
    /// Returns a collector holding nothing.
    #[must_use]
    pub fn new() -> Self {
        hold_the_seams_open();
        Self::default()
    }

    /// Returns every sample collected so far, in emission order.
    #[must_use]
    pub fn all(&self) -> Vec<Sample> {
        self.lock().clone()
    }

    /// Returns every sample of one quantity, in emission order.
    #[must_use]
    pub fn of(&self, quantity: &str) -> Vec<Sample> {
        self.lock()
            .iter()
            .filter(|sample| sample.quantity == quantity)
            .cloned()
            .collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Sample>> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl tracing::Subscriber for Samples {
    /// Deliberately `sometimes` rather than `always`: `tracing` caches a
    /// callsite's interest for the whole process, and an `always` cached
    /// by one thread would make every other thread build the event's
    /// fields whether or not it has a subscriber of its own.
    fn register_callsite(
        &self,
        metadata: &tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if metadata.target() == TARGET {
            tracing::subscriber::Interest::sometimes()
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == TARGET
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = SampleVisitor::default();
        event.record(&mut visitor);
        let Some(ms) = visitor.ms else {
            return;
        };
        self.lock().push(Sample {
            quantity: event.metadata().name(),
            ms,
            at_unix_ms: unix_ms(),
            fields: visitor.fields,
        });
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// Milliseconds since the Unix epoch, or zero on a machine whose clock
/// is set before it.
///
/// Zero rather than a panic: a sample is evidence, and losing the whole
/// run because one timestamp is unrepresentable would lose more evidence
/// than the timestamp is worth. An artifact full of zero timestamps is
/// also a legible complaint about the machine that produced it.
#[must_use]
pub fn unix_ms() -> u64 {
    UnixMillis::now().unwrap_or_default().0
}

/// Keeps timing callsites conditionally enabled across thread-local collectors.
/// `Samples::new` installs this once because tracing caches interest globally.
fn hold_the_seams_open() {
    static OPEN: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();
    let _ = OPEN.get_or_init(|| tracing::Dispatch::new(Listening));
}

/// The dispatcher [`hold_the_seams_open`] keeps: interested in the
/// seams, and useless for anything else.
struct Listening;

impl tracing::Subscriber for Listening {
    fn register_callsite(
        &self,
        metadata: &tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if metadata.target() == TARGET {
            tracing::subscriber::Interest::sometimes()
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::from_level(LEVEL))
    }

    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        false
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, _: &tracing::Event<'_>) {}

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

#[derive(Default)]
struct SampleVisitor {
    ms: Option<f64>,
    fields: Vec<(&'static str, String)>,
}

impl SampleVisitor {
    fn push(&mut self, field: &tracing::field::Field, value: String) {
        self.fields.push((field.name(), value));
    }
}

impl tracing::field::Visit for SampleVisitor {
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        if field.name() == "ms" {
            self.ms = Some(value);
        } else {
            self.push(field, value.to_string());
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.push(field, value.to_string());
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.push(field, value.to_string());
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.push(field, value.to_string());
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.push(field, value.to_owned());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn core::fmt::Debug) {
        self.push(field, format!("{value:?}"));
    }
}
