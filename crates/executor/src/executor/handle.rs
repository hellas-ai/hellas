//! In-process ingress for Work whose invocation is already journaled.
use super::{ExecutorHandle, ExecutorOwedRequest};
use crate::ExecutorError;
use tokio::sync::oneshot;
impl ExecutorHandle {
    pub(crate) async fn send_owed<T>(
        &self,
        make_request: impl FnOnce(oneshot::Sender<Result<T, ExecutorError>>) -> ExecutorOwedRequest,
    ) -> Result<T, ExecutorError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.owed_tx
            .send(make_request(reply_tx))
            .await
            .map_err(|_| ExecutorError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ExecutorError::ChannelClosed)?
    }
}
