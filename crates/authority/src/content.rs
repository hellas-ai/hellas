//! Concrete content evidence, sharing Work's current authority and response writer.
use crate::{
    grant_service::{Access, GrantWork},
    node::NodeCoordinator,
    operations::Operation,
    work_store::grant::{NodeStore, NodeStoreError},
};
use hellas_auth::authority::{AuthorityError, AuthorityId, Permission, ResourceId, UnixMillis};
use hellas_channel::work::admission::Cancellation;
use hellas_store::content::{GrantHandle, PinName, Scope, ScopeKind};

pub const READ: &str = "content.read";
pub const UPLOAD: &str = "content.upload";
pub const ACQUIRE: &str = "content.acquire";
pub const SET_PIN: &str = "content.pin.set";
pub const COLLECT: &str = "content.collect";
pub const RESOLVE: &str = "content.resolve";

/// A grant follows this exact name across CAS/removal/recreation, while its
/// policy is Granted. Owner policy and removal always close visibility.
pub fn pin_resource(authority: AuthorityId, pin: &PinName) -> ResourceId {
    ResourceId(hellas_auth::hash_tuple(
        "hellas.content.pin.resource.v1",
        &[authority.0.as_bytes(), pin.as_str().as_bytes()],
    ))
}
pub(crate) struct ContentBinding {
    pub(crate) node: NodeCoordinator,
    access: Access,
    kind: ScopeKind,
    operation: &'static str,
    work: Option<crate::model::grant::GrantJobAuthorizationV1>,
    pub(crate) cancellation: Cancellation,
    pub(crate) parent: Option<Cancellation>,
    service: Option<crate::grant_service::GrantService>,
}
impl ContentBinding {
    pub(crate) fn refresh(
        &self,
        store: &NodeStore,
        now: UnixMillis,
    ) -> Result<UnixMillis, NodeStoreError> {
        let result = (|| {
            if self.cancellation.is_cancelled()
                || self.parent.as_ref().is_some_and(Cancellation::is_cancelled)
            {
                return Err(AuthorityError::Revoked.into());
            }
            let authority = store.state().authority();
            match &self.kind {
                ScopeKind::Work { job, .. } => {
                    let work = self.work.as_ref().ok_or(AuthorityError::Denied)?;
                    let book = store
                        .state()
                        .channel(work.channel_id)
                        .map(|channel| channel.job_book());
                    if book.is_some_and(|book| book.terminal_by_id(job.id).is_some()) {
                        return Err(AuthorityError::Denied.into());
                    }
                    if let Some(service) = &self.service {
                        service.content_serving(book.is_some_and(|book| {
                            book.job_by_id(job.id)
                                .is_some_and(|job| job.provider_signature().is_some())
                        }))?;
                    }
                    let deadline = if let Some(accepted) = book
                        .and_then(|book| book.job_by_id(job.id))
                        .filter(|job| job.provider_signature().is_some())
                    {
                        if accepted.authorization() != work {
                            return Err(AuthorityError::Denied.into());
                        }
                        store.state().check_resource(work)?;
                        work.terminal_deadline_ms
                    } else {
                        work.acceptance_deadline_ms
                    };
                    if now >= deadline {
                        return Err(AuthorityError::Expired.into());
                    }
                    let client =
                        crate::model::grant::ChannelClient::of(self.access.caller(store, now)?)?;
                    let expires = if store.state().channel_binding(work.channel_id).is_some() {
                        self.access.authorize_channel(store, work.channel_id, now)?
                    } else {
                        if store.state().channel_id(work.grant_id, client) != Some(work.channel_id)
                        {
                            return Err(AuthorityError::Denied.into());
                        }
                        self.access.authorize(store, work.grant_id, now)?
                    };
                    if work.channel_id.0 != job.channel
                        || crate::model::grant::grant_work_id(store.state().network(), work)
                            != job.id
                    {
                        return Err(AuthorityError::Denied.into());
                    }
                    Ok(expires.min(deadline))
                }
                ScopeKind::Grant(handle) => self.access.authorize_permission(
                    store,
                    READ,
                    Permission {
                        operation: hellas_auth::authority::OperationId::new(READ)?,
                        resource: pin_resource(authority.authority(), &handle.pin),
                    },
                    now,
                ),
                ScopeKind::Owner => {
                    let owner = authority
                        .grant(authority.root_grant())
                        .ok_or(AuthorityError::Denied)?
                        .spec()
                        .subject;
                    if self.access.caller(store, now)?.subject() != owner {
                        return Err(AuthorityError::Denied.into());
                    }
                    self.access.authorize_permission(
                        store,
                        self.operation,
                        Operation::named(self.operation)?
                            .permission(authority.authority(), None)?,
                        now,
                    )
                }
                ScopeKind::Public => Err(AuthorityError::Denied.into()),
            }
        })();
        if result.is_err() {
            self.cancellation.cancel();
        }
        result
    }
}
impl GrantWork {
    /// The host selects this from the actual RPC method, never from request data.
    pub async fn content_owner(
        &self,
        operation: &'static str,
    ) -> Result<(Scope, hellas_wire::WriteAuthority), NodeStoreError> {
        if !matches!(
            operation,
            READ | UPLOAD | ACQUIRE | SET_PIN | COLLECT | RESOLVE
        ) {
            return Err(AuthorityError::Denied.into());
        }
        self.bind_content(Scope::Owner, operation, Cancellation::new(), None)
            .await
    }
    pub async fn content_read(
        &self,
        pin: PinName,
    ) -> Result<(Scope, hellas_wire::WriteAuthority), NodeStoreError> {
        self.bind_content(
            Scope::grant(GrantHandle {
                grant: self.access.authorization(),
                pin,
            }),
            READ,
            Cancellation::new(),
            None,
        )
        .await
    }
    /// Only the trusted admission path supplies a scope minted by the local store.
    pub async fn content_work(
        &self,
        scope: Scope,
        work: crate::model::grant::GrantJobAuthorizationV1,
        cancellation: Cancellation,
    ) -> Result<(Scope, hellas_wire::WriteAuthority), NodeStoreError> {
        if !matches!(scope.kind, ScopeKind::Work { .. }) {
            return Err(AuthorityError::Denied.into());
        }
        self.bind_content(
            scope,
            crate::grant_service::WORK_EXECUTE,
            cancellation,
            Some(work),
        )
        .await
    }
    async fn bind_content(
        &self,
        scope: Scope,
        operation: &'static str,
        cancellation: Cancellation,
        work: Option<crate::model::grant::GrantJobAuthorizationV1>,
    ) -> Result<(Scope, hellas_wire::WriteAuthority), NodeStoreError> {
        let node = self.service.node();
        let mut store = node.writer().await?;
        self.bind_content_locked(&mut store, scope, operation, cancellation, work)
    }
    pub(crate) fn content_work_locked(
        &self,
        store: &mut NodeStore,
        scope: Scope,
        work: crate::model::grant::GrantJobAuthorizationV1,
        cancellation: Cancellation,
    ) -> Result<(Scope, hellas_wire::WriteAuthority), NodeStoreError> {
        if !matches!(scope.kind, ScopeKind::Work { .. }) {
            return Err(AuthorityError::Denied.into());
        }
        self.bind_content_locked(
            store,
            scope,
            crate::grant_service::WORK_EXECUTE,
            cancellation,
            Some(work),
        )
    }
    fn bind_content_locked(
        &self,
        store: &mut NodeStore,
        scope: Scope,
        operation: &'static str,
        parent: Cancellation,
        work: Option<crate::model::grant::GrantJobAuthorizationV1>,
    ) -> Result<(Scope, hellas_wire::WriteAuthority), NodeStoreError> {
        let binding = ContentBinding {
            node: self.service.node(),
            access: self.access.clone(),
            kind: scope.kind.clone(),
            operation,
            cancellation: Cancellation::new(),
            parent: Some(parent),
            service: work.as_ref().map(|_| self.service.clone()),
            work,
        };
        binding.bind_locked(store, scope)
    }
}
impl ContentBinding {
    fn bind_locked(
        self,
        store: &mut NodeStore,
        scope: Scope,
    ) -> Result<(Scope, hellas_wire::WriteAuthority), NodeStoreError> {
        let binding = self;
        let now = binding.node.observed_time(store);
        binding.refresh(store, now)?;
        let binding = store.register_content(binding, now)?;
        let writer = crate::grant_service::delivery::content_authority(binding.clone());
        let monitor = crate::grant_service::delivery::content_authority(binding.clone());
        let ended = async move {
            let _ = futures::future::poll_fn(|cx| {
                monitor.poll_write(cx, &mut |_| std::task::Poll::Pending)
            })
            .await;
        };
        Ok((
            scope.bind(
                move || {
                    let binding = binding.clone();
                    async move {
                        let writer = binding
                            .node
                            .store
                            .lock_owned()
                            .await
                            .map_err(|_| hellas_store::content::Error::Denied)?;
                        Ok(move || {
                            binding
                                .refresh(&writer, binding.node.observed_time(&writer))
                                .map(|_| ())
                                .map_err(|_| hellas_store::content::Error::Denied)
                        })
                    }
                },
                ended,
            ),
            writer,
        ))
    }
}

impl NodeCoordinator {
    /// Bind owner evidence without requiring a provider enrollment or Work service.
    /// `operation` is selected by the host's RPC dispatch, never by request data.
    pub async fn content_owner_for_caller(
        &self,
        caller: hellas_auth::authority::AuthenticatedCaller,
        authorization: hellas_auth::authority::GrantId,
        operation: &'static str,
    ) -> Result<(Scope, hellas_wire::WriteAuthority), NodeStoreError> {
        self.bind_content(
            Access::for_caller(caller, authorization),
            Scope::Owner,
            operation,
        )
        .await
    }
    pub async fn content_owner_for_session(
        &self,
        session: hellas_auth::authority::AuthenticatedSession,
        binding: hellas_auth::Digest,
        authorization: hellas_auth::authority::GrantId,
        operation: &'static str,
    ) -> Result<(Scope, hellas_wire::WriteAuthority), NodeStoreError> {
        self.bind_content(
            Access::for_session(session, binding, authorization),
            Scope::Owner,
            operation,
        )
        .await
    }
    pub async fn content_read_for_session(
        &self,
        session: hellas_auth::authority::AuthenticatedSession,
        binding: hellas_auth::Digest,
        authorization: hellas_auth::authority::GrantId,
        pin: PinName,
    ) -> Result<(Scope, hellas_wire::WriteAuthority), NodeStoreError> {
        self.bind_content(
            Access::for_session(session, binding, authorization),
            Scope::grant(GrantHandle {
                grant: authorization,
                pin,
            }),
            READ,
        )
        .await
    }
    async fn bind_content(
        &self,
        access: Access,
        scope: Scope,
        operation: &'static str,
    ) -> Result<(Scope, hellas_wire::WriteAuthority), NodeStoreError> {
        if !matches!(
            operation,
            READ | UPLOAD | ACQUIRE | SET_PIN | COLLECT | RESOLVE
        ) {
            return Err(AuthorityError::Denied.into());
        }
        let mut store = self.writer().await?;
        ContentBinding {
            node: self.clone(),
            access,
            kind: scope.kind.clone(),
            operation,
            work: None,
            cancellation: Cancellation::new(),
            parent: None,
            service: None,
        }
        .bind_locked(&mut store, scope)
    }
}

#[cfg(test)]
mod tests;
