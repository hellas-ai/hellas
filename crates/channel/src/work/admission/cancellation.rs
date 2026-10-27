//! One-way cancellation shared by the writer and physical execution owner.
#[derive(Clone)]
pub struct Cancellation {
    changed: tokio::sync::watch::Sender<bool>,
    cleanup: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

impl std::fmt::Debug for Cancellation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cancellation")
            .field("cancelled", &self.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl Cancellation {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            changed: tokio::sync::watch::channel(false).0,
            cleanup: None,
        }
    }
    pub fn with_cleanup(cleanup: impl Fn() + Send + Sync + 'static) -> Self {
        Self {
            cleanup: Some(std::sync::Arc::new(cleanup)),
            ..Self::new()
        }
    }
    pub fn cancel(&self) {
        self.changed.send_replace(true);
        if let Some(cleanup) = &self.cleanup {
            cleanup();
        }
    }
    pub fn is_cancelled(&self) -> bool {
        *self.changed.borrow()
    }
    pub async fn cancelled(&self) {
        let mut receiver = self.changed.subscribe();
        let _ = receiver.wait_for(|cancelled| *cancelled).await;
    }
}

/// An interrupted or failed persistence operation cannot leave execution using
/// uncertain authority. Successful commits refresh current rights before disarming.
pub struct CancelOnFailure(pub Vec<Cancellation>);
impl Drop for CancelOnFailure {
    fn drop(&mut self) {
        for cancellation in &self.0 {
            cancellation.cancel();
        }
    }
}
