//! Per-connection RTT estimator. Default EWMA.

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EwmaLatency {
    /// Smoothing factor in `(0, 1]`. `1.0` = latest sample only.
    pub alpha: f64,
    /// Current estimate in milliseconds. `None` until first sample.
    pub est_ms: Option<f64>,
}

impl Default for EwmaLatency {
    fn default() -> Self {
        Self {
            alpha: 0.2,
            est_ms: None,
        }
    }
}

impl EwmaLatency {
    pub fn record(&mut self, sample_ms: f64) {
        if !(sample_ms.is_finite() && sample_ms >= 0.0) {
            // Negative or non-finite: protocol error — discard.
            return;
        }
        self.est_ms = Some(match self.est_ms {
            None => sample_ms,
            Some(prev) => self.alpha * sample_ms + (1.0 - self.alpha) * prev,
        });
    }

    pub fn get(&self) -> Option<f64> {
        self.est_ms
    }
}
