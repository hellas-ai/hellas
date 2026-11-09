//! Shared client state. Network waits never hold the journal lock.

use super::*;

/// Borrows a client endpoint for local state and journal operations.
/// Release the guard before waiting on a transport or a chain read.
pub trait ClientChannel: Send {
    /// # Errors
    /// [`EndpointError::Poisoned`] after a panic while holding the endpoint.
    fn client(
        &mut self,
    ) -> impl core::future::Future<
        Output = Result<impl DerefMut<Target = ClientEndpoint> + Send, EndpointError>,
    > + Send;

    /// Applies one certified read under the channel's driver.
    fn observe(
        &mut self,
        observed: &ObservedChannel<'_>,
    ) -> impl core::future::Future<Output = Result<u64, CatchUpError>> + Send;
}

impl ClientChannel for ClientEndpoint {
    async fn client(&mut self) -> Result<impl DerefMut<Target = Self> + Send, EndpointError> {
        Ok(self)
    }

    async fn observe(&mut self, observed: &ObservedChannel<'_>) -> Result<u64, CatchUpError> {
        Ok(ClientEndpoint::observe(self, observed).await?.cursor().0)
    }
}

/// The single request owner for a client channel. Requests retain exclusive
/// exchange ordering while the observer independently borrows the journal.
#[derive(Debug)]
pub struct ClientService {
    observer: ClientObserver,
}

impl ClientService {
    /// Release the journal once the request owner has joined its observer.
    pub async fn close(&mut self) -> Result<(), WorkStoreError> {
        self.observer
            .endpoint
            .lock_for_shutdown()
            .await
            .store
            .close()
            .await
    }

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

    /// Own preparation and its journal decision even if the requesting future ends.
    pub async fn propose(
        &mut self,
        proposal: &JobProposal,
        content: &(
            hellas_store::content::LocalStore,
            hellas_store::content::Scope,
        ),
    ) -> Result<AcceptWorkRequest, ProposeError> {
        let mut endpoint = self
            .observer
            .endpoint
            .lock_owned()
            .await
            .map_err(|_| EndpointError::Poisoned)?;
        let cancellation = admission::Cancellation::new();
        let mut guard = admission::CancelOnFailure(vec![cancellation.clone()]);
        let proposal = proposal.clone();
        let content = content.clone();
        let result = tokio::spawn(async move {
            endpoint
                .propose_owned(&proposal, &content, &cancellation)
                .await
        })
        .await
        .map_err(|_| EndpointError::Poisoned)?;
        guard.0.clear();
        result
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

    /// Supply the original caller input when replay retained only accounting.
    /// Policy and the existing signed authorization are checked before it is
    /// restored in memory. This neither accepts work nor writes payloads.
    pub async fn restore_input(
        &mut self,
        work_id: Digest,
        ready: &ReadyChannel,
        input: &hellas_rpc::protocol::invocation::PreparedInvocation,
    ) -> Result<(), DeliverError> {
        let mut endpoint = self.observer.endpoint().await?;
        bind(ready, &endpoint.store, &endpoint.signer, Role::Client)?;
        let job = endpoint
            .state()
            .job_by_id(work_id)
            .ok_or(DeliverError::NoSuchJob)?;
        crate::job::check_paid_input(
            ready.channel(),
            job.authorization(),
            ready.invocation_policy(),
            input,
        )?;
        endpoint.store.restore_client_input(
            work_id,
            input.canonical_bytes().map_err(PaidWorkError::from)?,
        )?;
        Ok(())
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

    /// Publishes readiness decided from the read the journal's cursor
    /// holds, as fresh as that read's certified block time.
    ///
    /// # Errors
    ///
    /// [`EndpointError::CatchingUp`] when the decision is newer than the
    /// cursor, [`EndpointError::ObservationStale`] when the cursor's read
    /// is too old, and the binding errors.
    pub async fn observe_ready(&self, ready: ReadyChannel) -> Result<(), EndpointError> {
        let mut endpoint = self.endpoint().await?;
        bind(&ready, &endpoint.store, &endpoint.signer, Role::Client)?;
        if ready.check_caught_up(endpoint.state().cursor().0).is_err() {
            return Err(EndpointError::CatchingUp);
        }
        let height = ready.finalized_height();
        let certified_at_ms = endpoint.state().certified_at_ms();
        endpoint
            .observation
            .as_mut()
            .ok_or(EndpointError::NotAdmitting)?
            .confirm(height, certified_at_ms)?;
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

    /// Takes exclusive authority to drive certified reads, not requests.
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

    async fn observe(&mut self, observed: &ObservedChannel<'_>) -> Result<u64, CatchUpError> {
        self.observer
            .drive()
            .map_err(|_| CatchUpError::Busy)?
            .observe(observed)
            .await
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
    /// Applies one certified read under the same lock used by payments.
    pub async fn observe(&mut self, observed: &ObservedChannel<'_>) -> Result<u64, CatchUpError> {
        let mut store = self.store().await?;
        observe(&mut store, observed, &Secp256k1Verifier::new()).await?;
        Ok(store.state().cursor().0)
    }

    /// Drives a retained close without blocking ordinary state access.
    pub async fn advance_close<T>(
        &mut self,
        observed: &ObservedChannel<'_>,
        sink: &T,
    ) -> Result<CloseProgress, CatchUpError>
    where
        T: TxSink + ?Sized,
    {
        advance_close(observed, sink, self, &Secp256k1Verifier::new()).await
    }
}

#[cfg(test)]
mod proposal_tests {
    use super::*;
    use crate::test_support::channel as fixture;
    use hellas_store::content::{ContentStore as _, *};

    async fn service(root: &std::path::Path) -> (ClientService, DiskStore, u64) {
        let ready = fixture::ready();
        let input = fixture::bundle(1);
        let bytes = input.canonical_bytes().unwrap();
        let root_bytes = fixture::environment().canonical_bytes().unwrap();
        let authorization = crate::job::propose(
            ready.channel(),
            ready.invocation_policy(),
            ready.payment_policy(),
            &input,
            1,
            fixture::deadlines(),
        )
        .unwrap();
        let facts = crate::job::check_paid_input(
            ready.channel(),
            &authorization,
            ready.invocation_policy(),
            &input,
        )
        .unwrap();
        let closure = vec![
            ContentRef::for_bytes(&bytes),
            ContentRef::for_bytes(&root_bytes),
        ];
        let capacity = closure.iter().map(|object| object.bytes()).sum::<u64>()
            + facts.max_spool_bytes
            + crate::content::tree_reservation(&closure, facts.max_spool_bytes).unwrap();
        let location = hellas_private::StoreLocation::for_test(root);
        let content = DiskStore::open(
            location.child("content"),
            vec![],
            IndexMode::Resume,
            Some(capacity),
            Reservations::ram(crate::content::DEFAULT_MAX_STAGING_BYTES),
            false,
        )
        .await
        .unwrap();
        let mut store = ChannelStore::open(
            &location,
            ready.channel().clone(),
            fixture::settlement(),
            Role::Client,
            fixture::origin(),
            content.clone(),
            &Secp256k1Verifier::new(),
        )
        .await
        .unwrap();
        content.finish_recovery().await.unwrap();
        fixture::advance(&mut store, fixture::CURSOR).await;
        let service = ClientService::new(
            ClientEndpoint::new(ready.clone(), store, fixture::client()).unwrap(),
        );
        service.observer().observe_ready(ready).await.unwrap();
        (service, content, capacity)
    }

    #[tokio::test]
    async fn failed_retained_output_admission_releases_input_before_the_next_proposal() {
        let root = tempfile::tempdir().unwrap();
        let (mut client, node, capacity) = service(root.path()).await;
        let input = fixture::bundle(1);
        let input_bytes = input.canonical_bytes().unwrap().len() as u64
            + fixture::environment().canonical_bytes().unwrap().len() as u64;
        let foreign = node
            .open_work(
                JobId {
                    channel: Digest::hash(b"other channel"),
                    id: Digest::hash(b"other job"),
                },
                vec![],
                0,
            )
            .await
            .unwrap();
        node.reserve_output(&foreign, capacity - input_bytes)
            .await
            .unwrap();
        let prior = node.stats().unwrap();
        let ram = node.ram_pool().held();
        let source = fixture::program_content().await;
        let error = client
            .propose(
                &JobProposal {
                    prepared_input: input,
                    deadlines: fixture::deadlines(),
                },
                &source,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ProposeError::Store(WorkStoreError::Content(Error::Capacity))
        ));
        assert_eq!(node.stats().unwrap().used, prior.used);
        assert_eq!(node.stats().unwrap().outstanding, prior.outstanding);
        assert_eq!(node.ram_pool().held(), ram);
        assert_eq!(
            client
                .with_state(|state| state.jobs().count())
                .await
                .unwrap(),
            0
        );
        node.end_work(&foreign).await.unwrap();
        client
            .propose(
                &JobProposal {
                    prepared_input: fixture::bundle(2),
                    deadlines: fixture::deadlines(),
                },
                &source,
            )
            .await
            .unwrap();
        assert_eq!(
            client
                .with_state(|state| state.jobs().count())
                .await
                .unwrap(),
            1
        );
        node.close().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancelled_proposal_keeps_owning_admission_until_exact_cleanup_finishes() {
        let root = tempfile::tempdir().unwrap();
        let (mut client, node, _) = service(root.path()).await;
        let source = fixture::program_content().await;
        let (entered, waiting) = std::sync::mpsc::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let blocked = Arc::new(std::sync::Mutex::new(blocked));
        let once = Arc::new(AtomicBool::new(true));
        let bound = Scope::Owner.bind(
            move || {
                let blocked = blocked.clone();
                let entered = entered.clone();
                let once = once.clone();
                async move {
                    Ok(move || {
                        if once.swap(false, Ordering::AcqRel) {
                            entered.send(()).unwrap();
                            blocked.lock().unwrap().recv().unwrap();
                        }
                        Ok(())
                    })
                }
            },
            std::future::pending,
        );
        let holding = node.clone();
        let hold = tokio::spawn(async move {
            holding.pins(&bound, "", Cursor::default()).await.unwrap();
        });
        waiting
            .recv_timeout(crate::test_support::HANG_GUARD)
            .unwrap();
        let observer = client.observer();
        let proposal = JobProposal {
            prepared_input: fixture::bundle(1),
            deadlines: fixture::deadlines(),
        };
        let mut request = Box::pin(client.propose(&proposal, &source));
        assert!(futures::poll!(request.as_mut()).is_pending());
        drop(request);
        let mut observed = Box::pin(observer.with_state(|state| state.jobs().count()));
        assert!(
            futures::poll!(observed.as_mut()).is_pending(),
            "owned proposal still holds the writer"
        );
        release.send(()).unwrap();
        hold.await.unwrap();
        assert_eq!(
            tokio::time::timeout(crate::test_support::HANG_GUARD, observed)
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert_eq!(node.stats().unwrap().used, 0);
        assert_eq!(node.stats().unwrap().outstanding, 0);
        assert_eq!(node.ram_pool().held(), 0);
        client
            .propose(
                &JobProposal {
                    prepared_input: fixture::bundle(2),
                    deadlines: fixture::deadlines(),
                },
                &source,
            )
            .await
            .unwrap();
        node.close().await;
    }
}
