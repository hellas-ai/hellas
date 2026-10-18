//! Verified application evidence; binding a handle does not grant future access.
use super::*;
use hellas_auth::authority::{
    AuthenticatedCaller, AuthenticatedSession, AuthorityError, AuthorityId, GrantId, ResourceId,
};

pub const WORK_EXECUTE: &str = "work.execute";

/// The configured allowance is an exact Work resource, including its policies.
/// It is independent of the application credential and client transport.
pub fn allowance_resource(authority: AuthorityId, allowance: GrantId) -> ResourceId {
    ResourceId(hellas_auth::hash_tuple(
        "hellas.work.allowance.resource.v1",
        &[authority.0.as_bytes(), &allowance.0],
    ))
}

#[derive(Clone)]
pub(crate) struct Access {
    evidence: Arc<Evidence>,
    authorization: GrantId,
}
enum Evidence {
    Native(AuthenticatedCaller),
    Session(AuthenticatedSession, Digest),
}

impl Access {
    pub(super) fn decision(&self, action: &'static str) -> crate::audit::Decision {
        let credential = match self.evidence.as_ref() {
            Evidence::Native(caller) => caller.credential(),
            Evidence::Session(session, _) => session.credential(),
        };
        crate::audit::Decision::new(action, Some(self.authorization), Some(credential))
    }
    pub(super) fn observe(
        &self,
        decision: &mut crate::audit::Decision,
        store: &NodeStore,
        now: UnixMillis,
    ) {
        decision.observe(store.state().authority(), self.caller(store, now).ok(), now);
    }
    pub(super) fn application<'a>(
        &'a self,
        store: &NodeStore,
        now: UnixMillis,
    ) -> Result<(&'a AuthenticatedCaller, GrantId), NodeStoreError> {
        Ok((self.caller(store, now)?, self.authorization))
    }
    pub(crate) fn caller<'a>(
        &'a self,
        store: &NodeStore,
        now: UnixMillis,
    ) -> Result<&'a AuthenticatedCaller, NodeStoreError> {
        Ok(match self.evidence.as_ref() {
            Evidence::Native(caller) => caller,
            Evidence::Session(session, binding) => {
                session.authenticate(store.state().authority(), *binding, now)?
            }
        })
    }
    pub(crate) fn authorize_channel(
        &self,
        store: &NodeStore,
        channel: ChannelId,
        now: UnixMillis,
    ) -> Result<UnixMillis, NodeStoreError> {
        let binding = store
            .state()
            .channel_binding(channel)
            .ok_or(AuthorityError::Denied)?;
        let expires = self.authorize(store, binding.grant, now)?;
        if binding.client != self.caller(store, now)?.subject() {
            return Err(AuthorityError::Denied.into());
        }
        Ok(expires)
    }
    pub(crate) fn authorize(
        &self,
        store: &NodeStore,
        allowance: GrantId,
        now: UnixMillis,
    ) -> Result<UnixMillis, NodeStoreError> {
        let mut decision = self.decision(WORK_EXECUTE);
        let result = (|| {
            store.check_authority()?;
            let now = store.time(now)?;
            self.observe(&mut decision, store, now);
            let authority = store.state().authority();
            let caller = self.caller(store, now)?;
            let lineage = authority.authorize_caller(
                caller,
                self.authorization,
                &crate::operations::Operation::named(WORK_EXECUTE)?
                    .permission(authority.authority(), Some(allowance))?,
                now,
            )?;
            let mut expires = caller.expires();
            if let Evidence::Session(session, _) = self.evidence.as_ref() {
                expires = expires.min(session.expires());
            }
            for (id, _) in lineage {
                let grant = authority.grant(id).ok_or(AuthorityError::Denied)?;
                expires = expires.min(grant.spec().expires);
            }
            Ok(expires)
        })();
        decision.finish(result)
    }
}

/// A caller-bound native/RPC handle. Every operation checks current authority
/// under the node writer; retaining this handle never retains revoked rights.
#[derive(Clone)]
pub struct GrantWork {
    pub(super) service: GrantService,
    pub(super) access: Access,
}
impl GrantService {
    pub fn for_caller(&self, caller: AuthenticatedCaller, authorization: GrantId) -> GrantWork {
        self.with_evidence(Evidence::Native(caller), authorization)
    }

    /// Hosts supply their connection-owned session and independently derived binding.
    pub fn for_session(
        &self,
        session: AuthenticatedSession,
        binding: Digest,
        authorization: GrantId,
    ) -> GrantWork {
        self.with_evidence(Evidence::Session(session, binding), authorization)
    }

    fn with_evidence(&self, evidence: Evidence, authorization: GrantId) -> GrantWork {
        GrantWork {
            service: self.clone(),
            access: Access {
                evidence: Arc::new(evidence),
                authorization,
            },
        }
    }
}
impl GrantWork {
    /// Hosts recheck their session before decoding another RPC. Exact execution
    /// permission is still checked under the writer at each protected effect.
    pub async fn authenticate(&self) -> Result<(), NodeStoreError> {
        let mut decision = self.access.decision("work.authenticate");
        let result = async {
            let (store, now) = self.service.node.lock().await?;
            self.access.observe(&mut decision, &store, now);
            store
                .state()
                .authority()
                .record_caller(self.access.caller(&store, now)?, now)?;
            Ok(())
        }
        .await;
        decision.finish(result)
    }
    pub async fn standing(&self, request: &GetStandingRequest) -> GetStandingResponse {
        self.service.standing(&self.access, request).await
    }
    pub async fn accept(&self, request: &AcceptWorkRequest) -> AcceptWorkResponse {
        self.service.accept(&self.access, request).await
    }
    pub fn stream(&self, request: DeliverResultRequest) -> PaidResultStream {
        self.service.stream(self.access.clone(), request)
    }
}
