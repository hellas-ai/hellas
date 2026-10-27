//! Funding-independent gateway input preparation and bounded output delivery.
use futures::stream::BoxStream;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};

pub const OUTPUT_BUFFER_BYTES: usize = 2 * hellas_channel::work_store::journal::MAX_RECORD_BYTES;
pub const OUTPUT_EVENT_OVERHEAD: usize = 1024;
pub const OUTPUT_BUFFER_EVENTS: usize = OUTPUT_BUFFER_BYTES / OUTPUT_EVENT_OVERHEAD;
pub type BufferedEvent<E, X> = (Result<E, X>, OwnedSemaphorePermit);
fn output_error(
    error: impl std::error::Error + Send + Sync + 'static,
) -> hellas_gateway::WorkGatewayError {
    hellas_gateway::WorkGatewayError::Execution(Box::new(error))
}
pub(crate) fn fetch_prefix(
    chunk: hellas_rpc::protocol::invocation::output::ArtifactChunk,
    pending: &mut Vec<u8>,
) -> Result<Vec<hellas_rpc::output::OutputEvent>, hellas_gateway::WorkGatewayError> {
    use hellas_rpc::protocol::invocation::fetch;
    if chunk.name != fetch::RESPONSE_EVENTS || chunk.format != fetch::RESPONSE_EVENTS_FORMAT {
        return Err(output_error(std::io::Error::other(
            "Fetch artifact identity",
        )));
    }
    pending.extend_from_slice(chunk.bytes.as_bytes());
    let mut events = Vec::new();
    while let Some(header) = pending.get(..4) {
        let length = u32::from_be_bytes(header.try_into().map_err(output_error)?) as usize;
        if length > hellas_rpc::fetch::MAX_FETCH_OUTPUT_PAYLOAD_BYTES {
            return Err(output_error(std::io::Error::other(
                "Fetch frame exceeds payload bound",
            )));
        }
        let end = 4 + length;
        if pending.len() < end {
            break;
        }
        events.push(
            hellas_rpc::fetch::decode_fetch_event_payload(&pending[4..end])
                .map_err(output_error)?,
        );
        pending.drain(..end);
    }
    Ok(events)
}
pub(crate) fn fetch_terminal(
    output: &hellas_rpc::protocol::invocation::output::InvocationOutput,
    provider: &hellas_auth::PublicKey,
) -> Result<hellas_rpc::output::OutputEvent, hellas_gateway::WorkGatewayError> {
    let response = hellas_rpc::protocol::invocation::fetch::decode_output(output, provider)
        .map_err(output_error)?;
    let (_, terminal) = response.output_event_payloads();
    Ok(hellas_rpc::fetch::decode_fetch_terminal_payload(terminal)
        .map_err(output_error)?
        .to_output_event())
}

pub fn emit<E, X>(
    sender: &mpsc::Sender<BufferedEvent<E, X>>,
    overflow: &watch::Sender<bool>,
    budget: &Arc<Semaphore>,
    event: Result<E, X>,
    bytes: usize,
) {
    if *overflow.borrow() || sender.is_closed() {
        return;
    }
    let bytes = bytes.saturating_add(OUTPUT_EVENT_OVERHEAD);
    let permits = u32::try_from(bytes)
        .ok()
        .and_then(|n| budget.clone().try_acquire_many_owned(n).ok());
    let Some(permits) = permits else {
        overflow.send_replace(true);
        return;
    };
    if matches!(
        sender.try_send((event, permits)),
        Err(mpsc::error::TrySendError::Full(_))
    ) {
        overflow.send_replace(true);
    }
}
pub fn response_stream<E: Send + 'static, X: Send + 'static>(
    mut receiver: mpsc::Receiver<BufferedEvent<E, X>>,
    mut overflow: watch::Receiver<bool>,
    slow_consumer: fn() -> X,
) -> BoxStream<'static, Result<E, X>> {
    Box::pin(async_stream::try_stream! {
        loop {
            if *overflow.borrow() { receiver.close(); Err(slow_consumer())?; }
            let event = tokio::select! {
                biased;
                _ = overflow.changed(), if overflow.has_changed().is_ok() => continue,
                event = receiver.recv() => event,
            };
            match event { Some((event, permit)) => { drop(permit); yield event?; }, None => return }
        }
    })
}

/// Owns accepted tasks until their futures physically terminate. Drain polls the
/// handles in place so dropping a drain future cannot detach unfinished work.
#[derive(Default)]
pub(crate) struct WorkTasks {
    state: std::sync::Mutex<TaskState>,
    draining: tokio::sync::Mutex<()>,
}
#[derive(Default)]
struct TaskState {
    closed: bool,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    failure: Option<Arc<tokio::task::JoinError>>,
}
impl TaskState {
    fn poll(&mut self, cx: &mut std::task::Context<'_>, finished_only: bool) {
        use std::{future::Future as _, pin::Pin, task::Poll};
        let failure = &mut self.failure;
        self.tasks.retain_mut(|task| {
            if finished_only && !task.is_finished() {
                return true;
            }
            match Pin::new(task).poll(cx) {
                Poll::Pending => true,
                Poll::Ready(Ok(())) => false,
                Poll::Ready(Err(error)) => {
                    failure.get_or_insert_with(|| Arc::new(error));
                    false
                }
            }
        });
    }
}
impl WorkTasks {
    pub fn spawn(
        &self,
        future: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), hellas_gateway::WorkGatewayBusy> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| hellas_gateway::WorkGatewayBusy)?;
        if state.closed {
            return Err(hellas_gateway::WorkGatewayBusy);
        }
        let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
        state.poll(&mut cx, true);
        state.tasks.push(tokio::spawn(future));
        Ok(())
    }

    pub fn close(&self) {
        match self.state.lock() {
            Ok(mut state) => state.closed = true,
            Err(error) => error.into_inner().closed = true,
        }
    }

    pub async fn drain(&self) -> Result<(), hellas_gateway::WorkShutdownError> {
        use hellas_gateway::WorkShutdownError;
        self.close();
        let _draining = self.draining.lock().await;
        std::future::poll_fn(|cx| {
            let (mut state, poisoned) = match self.state.lock() {
                Ok(state) => (state, false),
                Err(error) => (error.into_inner(), true),
            };
            state.poll(cx, false);
            if !state.tasks.is_empty() {
                return std::task::Poll::Pending;
            }
            std::task::Poll::Ready(if let Some(error) = &state.failure {
                Err(WorkShutdownError::Task(error.clone()))
            } else if poisoned {
                Err(WorkShutdownError::Poisoned)
            } else {
                Ok(())
            })
        })
        .await
    }
}

#[cfg(test)]
mod task_tests {
    use super::WorkTasks;
    use hellas_gateway::WorkShutdownError;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn cancelled_drain_keeps_tasks_even_when_state_is_poisoned() {
        for poison in [false, true] {
            let tasks = WorkTasks::default();
            let (release, released) = oneshot::channel();
            let (finished, completed) = oneshot::channel();
            tasks
                .spawn(async move {
                    released.await.unwrap();
                    finished.send(()).unwrap();
                })
                .unwrap();
            if poison {
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let _state = tasks.state.lock().unwrap();
                        panic!("inject poisoned task state");
                    }))
                    .is_err()
                );
            }
            {
                let mut first = std::pin::pin!(tasks.drain());
                assert!(futures::poll!(&mut first).is_pending());
            }
            assert!(tasks.spawn(async {}).is_err());
            let mut second = std::pin::pin!(tasks.drain());
            assert!(futures::poll!(&mut second).is_pending());
            release.send(()).unwrap();
            let result = second.await;
            completed.await.unwrap();
            if poison {
                assert!(matches!(result, Err(WorkShutdownError::Poisoned)));
            } else {
                result.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn task_panic_is_reported_after_other_work_finishes() {
        let tasks = WorkTasks::default();
        tasks
            .spawn(async {
                panic!("inject gateway task panic");
            })
            .unwrap();
        let (release, released) = oneshot::channel();
        tasks
            .spawn(async {
                released.await.unwrap();
            })
            .unwrap();
        let mut draining = std::pin::pin!(tasks.drain());
        assert!(futures::poll!(&mut draining).is_pending());
        tokio::task::yield_now().await;
        assert!(futures::poll!(&mut draining).is_pending());
        release.send(()).unwrap();
        assert!(matches!(draining.await, Err(WorkShutdownError::Task(error)) if error.is_panic()));
    }
}
