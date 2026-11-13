//! The three live operations run directly against the daemon.
use super::*;
use hellas_authority::node::{HOST_CANCEL_JOB, HOST_STATUS};

impl ControlSession {
    pub(super) async fn configure_daemon(
        &self,
        request: ConfigureRequest,
    ) -> Result<ConfigureResponse, WireStatus> {
        self.caller().await?;
        let core = self
            .core
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or_else(unsupported)?;
        if request.document.len() > MAX_COMMAND_BYTES {
            return Err(invalid());
        }
        let document = serde_json::from_slice(&request.document).map_err(|_| invalid())?;
        let revision = core
            .configure(
                self.session.clone(),
                self.binding,
                grant_id(&request.authorization)?,
                Revision(request.expected_revision),
                document,
            )
            .await
            .map_err(|error| {
                match error.downcast::<NodeStoreError>() {
                    Ok(error) => node_error(*error),
                    // Prepared inputs can contain keys. They are never reflected in a control error.
                    Err(_) => {
                        WireStatus::new(WireCode::FailedPrecondition, "configuration rejected")
                    }
                }
            })?;
        Ok(ConfigureResponse {
            revision: revision.0,
        })
    }

    pub(super) async fn watch_daemon(
        &self,
        request: WatchRequest,
    ) -> Result<hellas_rpc::call::ResponseStream<WatchResponse>, WireStatus> {
        let authorization = grant_id(&request.authorization)?;
        let core = self
            .core
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or_else(unsupported)?;
        let (view, mut events) = self
            .node
            .host_action(self.caller().await?, authorization, HOST_STATUS, |_| {
                core.watch()
            })
            .await
            .map_err(node_error)?;
        let snapshot = serde_json::to_vec(&view).map_err(|_| unavailable())?;
        let session = self.clone();
        Ok(hellas_rpc::call::ResponseStream::new(
            async_stream::try_stream! {
                yield WatchResponse { update: Some(watch_response::Update::Snapshot(snapshot)) };
                loop {
                    let event = events.recv().await.map_err(|_| WireStatus::new(WireCode::ResourceExhausted, "watch lost events; reconnect for a new snapshot"))?;
                    session.node.host_action(session.caller().await?, authorization, HOST_STATUS, |_| ()).await.map_err(node_error)?;
                    let event = serde_json::to_vec(&event).map_err(|_| unavailable())?;
                    yield WatchResponse { update: Some(watch_response::Update::Event(event)) };
                }
            },
        ))
    }

    pub(super) async fn cancel_daemon_job(
        &self,
        request: CancelJobRequest,
    ) -> Result<CancelJobResponse, WireStatus> {
        let core = self
            .core
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or_else(unsupported)?;
        let cancelled = self
            .node
            .host_action(
                self.caller().await?,
                grant_id(&request.authorization)?,
                HOST_CANCEL_JOB,
                |_| core.jobs.cancel(request.id),
            )
            .await
            .map_err(node_error)?;
        Ok(CancelJobResponse { cancelled })
    }
}
