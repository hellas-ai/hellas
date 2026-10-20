//! Shared client state. Network waits never hold the journal lock.

use super::*;

/// Borrows a client endpoint for local state and journal operations.
/// Release the guard before waiting on a transport or finalized history.
pub trait ClientChannel: Send {
    /// # Errors
    /// [`EndpointError::Poisoned`] after a panic while holding the endpoint.
    fn client(
        &mut self,
    ) -> impl core::future::Future<
        Output = Result<impl DerefMut<Target = ClientEndpoint> + Send, EndpointError>,
    > + Send;
}

impl ClientChannel for ClientEndpoint {
    async fn client(&mut self) -> Result<impl DerefMut<Target = Self> + Send, EndpointError> {
        Ok(self)
    }
}

/// The single request owner for a client channel. Requests retain exclusive
/// exchange ordering while the observer independently borrows the journal.
#[derive(Debug)]
pub struct ClientService {
    observer: ClientObserver,
}

impl ClientService {
    /// Starts sharing an already opened journal with its observer.
    #[must_use]
    pub fn new(mut endpoint: ClientEndpoint) -> Self {
        endpoint.observation = Some(Observation::default());
        Self {
            observer: ClientObserver {
                endpoint: Arc::new(EndpointLock::new(endpoint)),
                driving: Arc::new(AtomicBool::new(false)),
            },
        }
    }

    /// Gives the chain task observation authority, never payment authority.
    #[must_use]
    pub fn observer(&self) -> ClientObserver {
        self.observer.clone()
    }

    /// Reads local accounting without holding a borrow across an await.
    pub async fn with_state<R>(
        &self,
        read: impl FnOnce(&Channel) -> R,
    ) -> Result<R, EndpointError> {
        self.observer.with_state(read).await
    }

    /// Checks the observer's current admission decision locally.
    pub async fn readiness(&self) -> Result<ReadyChannel, EndpointError> {
        self.observer.readiness().await
    }
}

/// Shares finalized-history and readiness updates with the request owner.
/// Cloning this handle cannot create another payer. Driving remains exclusive.
#[derive(Clone, Debug)]
pub struct ClientObserver {
    endpoint: Arc<EndpointLock<ClientEndpoint>>,
    driving: Arc<AtomicBool>,
}

impl ClientObserver {
    async fn endpoint(&self) -> Result<EndpointGuard<'_, ClientEndpoint>, EndpointError> {
        self.endpoint
            .lock()
            .await
            .map_err(|_| EndpointError::Poisoned)
    }

    /// Reads local state without holding it across an await.
    pub async fn with_state<R>(
        &self,
        read: impl FnOnce(&Channel) -> R,
    ) -> Result<R, EndpointError> {
        Ok(read(self.endpoint().await?.state()))
    }

    /// Publishes a coherent snapshot only after its history has been applied.
    pub async fn observe_ready(
        &self,
        ready: ReadyChannel,
        started: ObservationTime,
        max_age: std::time::Duration,
    ) -> Result<(), EndpointError> {
        let mut endpoint = self.endpoint().await?;
        bind(&ready, &endpoint.store, &endpoint.signer, Role::Client)?;
        if ready.check_caught_up(endpoint.state().cursor().0).is_err() {
            return Err(EndpointError::CatchingUp);
        }
        let height = ready.finalized_height();
        endpoint
            .observation
            .as_mut()
            .ok_or(EndpointError::NotAdmitting)?
            .confirm(height, started, max_age);
        endpoint.ready = Some(ready);
        Ok(())
    }

    /// Returns local readiness; never contacts a validator.
    pub async fn readiness(&self) -> Result<ReadyChannel, EndpointError> {
        let endpoint = self.endpoint().await?;
        endpoint
            .observation
            .as_ref()
            .ok_or(EndpointError::NotAdmitting)?
            .check()?;
        if endpoint.state().is_closing() {
            return Err(EndpointError::NotAdmitting);
        }
        endpoint.ready.clone().ok_or(EndpointError::NotAdmitting)
    }

    /// Stops new signatures while the observer reconnects or shuts down.
    pub async fn suspend(&self) -> Result<(), EndpointError> {
        self.endpoint()
            .await?
            .observation
            .as_mut()
            .ok_or(EndpointError::NotAdmitting)?
            .suspend();
        Ok(())
    }

    /// Takes exclusive authority to drive finalized history, not requests.
    pub fn drive(&self) -> Result<ClientDriver<'_>, EndpointError> {
        self.driving
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| EndpointError::CatchingUp)?;
        Ok(ClientDriver { service: self })
    }
}

impl ClientChannel for ClientService {
    async fn client(
        &mut self,
    ) -> Result<impl DerefMut<Target = ClientEndpoint> + Send, EndpointError> {
        self.observer.endpoint().await
    }
}

/// The client's one chain driver. Dropping it releases driving authority.
pub struct ClientDriver<'a> {
    service: &'a ClientObserver,
}

impl Drop for ClientDriver<'_> {
    fn drop(&mut self) {
        self.service.driving.store(false, Ordering::Release);
    }
}

impl CloseChannel for ClientDriver<'_> {
    async fn store(&mut self) -> Result<impl DerefMut<Target = ChannelStore> + Send, CatchUpError> {
        Ok(ChannelStoreGuard::Client(
            self.service
                .endpoint()
                .await
                .map_err(|_| CatchUpError::Busy)?,
        ))
    }
}

impl ClientDriver<'_> {
    /// Applies a verified block under the same lock used by payments.
    pub async fn observe_finalized(&mut self, block: &FinalizedWork) -> Result<(), CatchUpError> {
        observe(&mut *self.store().await?, block, &Secp256k1Verifier::new()).await?;
        Ok(())
    }

    /// Fetches missing blocks without borrowing the journal across network I/O.
    pub async fn catch_up<S: FinalizedBlocks + ?Sized>(
        &mut self,
        source: &S,
    ) -> Result<u64, CatchUpError> {
        let Some(latest) = source.latest_height().await? else {
            return Ok(self.store().await?.state().cursor().0);
        };
        self.catch_up_to(source, latest).await
    }

    /// Applies a fixed snapshot's history without querying a moving chain tip.
    pub async fn catch_up_to<S: FinalizedBlocks + ?Sized>(
        &mut self,
        source: &S,
        latest: u64,
    ) -> Result<u64, CatchUpError> {
        let next = self.store().await?.state().cursor().0.saturating_add(1);
        for height in next..=latest {
            let block = source
                .block_at(height)
                .await?
                .ok_or(CatchUpError::Missing { height })?;
            self.observe_finalized(&block).await?;
        }
        Ok(self.store().await?.state().cursor().0)
    }

    /// Drives a retained close without blocking ordinary state access.
    pub async fn advance_close<S, T>(
        &mut self,
        source: &S,
        sink: &T,
    ) -> Result<CloseProgress, CatchUpError>
    where
        S: FinalizedBlocks + ?Sized,
        T: TxSink + ?Sized,
    {
        advance_close(source, sink, self, &Secp256k1Verifier::new()).await
    }
}
