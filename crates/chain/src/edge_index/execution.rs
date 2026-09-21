//! Shared admission, deadline, and error policy for both EdgeIndex transports.
use super::{
    EdgeIndex, EdgeIndexError,
    types::{IndexError, SCHEMA_VERSION},
};

impl EdgeIndex {
    pub(super) async fn execute<T: Send + 'static>(
        &self,
        query: impl FnOnce(Self) -> Result<T, EdgeIndexError> + Send + 'static,
    ) -> Result<T, EdgeIndexError> {
        let permit = self.permits.clone().try_acquire_owned().map_err(|_| {
            EdgeIndexError::unavailable("index query capacity exhausted; retry later")
        })?;
        let index = self.clone();
        let task = tokio::task::spawn_blocking(move || {
            // The permit remains held if a timed-out query has not yet stopped.
            let _permit = permit;
            query(index)
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .map_err(|_| EdgeIndexError::unavailable("index query deadline exceeded; retry later"))?
            .map_err(|_| EdgeIndexError::unavailable("index query failed"))?
    }
}

impl EdgeIndexError {
    pub(super) fn into_details(self) -> (u16, IndexError) {
        (
            self.status,
            IndexError {
                schema_version: SCHEMA_VERSION,
                code: self.code.into(),
                message: self.message,
                envelope: self.snapshot.map(|value| *value),
            },
        )
    }
}
