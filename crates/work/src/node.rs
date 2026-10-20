//! Checked authority service sharing the node's existing durable writer.
use crate::endpoint_lock::{EndpointGuard, EndpointLock};
use crate::operations::validate_scope;
use crate::work_store::grant::{NodeStore, NodeStoreError};
use hellas_auth::authority::*;
use hellas_auth::{Digest, ProducerSigningKey};
use hellas_kernel::{PayloadHash, SoftPasskey, WebAuthnAssertion};
use std::sync::Arc;
mod host;
pub use host::{
    GATEWAY_INVOKE, HOST_GATEWAY_ACCESS, HOST_GATEWAY_CONFIGURE, HOST_PROVIDER_BIND,
    HOST_PROVIDER_CONFIGURE, HOST_STATUS, MachineCapacity, NodeStatus, WORK_CAPACITY_CONFIGURE,
    host_resource, machine_resource,
};

/// The key a client proves an authority session with.
#[derive(Clone, Copy)]
pub enum SessionKey<'a> {
    /// The credential subject's passkey: a passkey session, as step-up needs.
    Passkey(&'a SoftPasskey),
    /// The node key the credential is bound to: a daily session.
    Node(&'a ProducerSigningKey),
}

impl SessionKey<'_> {
    /// Answer `challenge` for `credential`, after checking it names the
    /// expected authority and this connection's binding.
    pub fn prove(
        self,
        challenge: &SessionChallenge,
        authority: AuthorityId,
        binding: Digest,
        credential: CredentialId,
    ) -> Result<SessionProof, AuthorityError> {
        match self {
            Self::Node(key) => challenge.sign_daily(authority, binding, credential, key),
            Self::Passkey(passkey) => {
                let digest = challenge.proof_digest(authority, binding, credential)?;
                let envelope = passkey
                    .sign(PayloadHash::from_bytes(*digest.as_bytes()))
                    .map_err(|_| AuthorityError::Credential)?;
                passkey_assertion(&envelope).map(SessionProof::Passkey)
            }
        }
    }
}

/// A kernel-envelope assertion, as a software passkey produces it.
pub fn passkey_assertion(envelope: &WebAuthnAssertion) -> Result<PasskeyAssertion, AuthorityError> {
    let mut signature = [0; 64];
    let (r, s) = signature.split_at_mut(32);
    r.copy_from_slice(envelope.r());
    s.copy_from_slice(envelope.s());
    PasskeyAssertion::from_envelope(signature, envelope.webauthn_data().as_slice())
}

/// Cloneable service handle, not caller authority. No method exposes a mutable
/// store or accepts a caller identity/record in place of verified evidence.
#[derive(Clone)]
pub struct NodeCoordinator {
    pub(crate) store: Arc<EndpointLock<NodeStore>>,
    pub(crate) clock: Arc<dyn Fn() -> UnixMillis + Send + Sync>,
    pub(crate) changed: Arc<tokio::sync::Notify>,
}

/// Wake readers after a mutation attempt, including a cancelled/poisoned append.
pub(crate) struct ChangeNotification(pub(crate) Arc<tokio::sync::Notify>);
impl Drop for ChangeNotification {
    fn drop(&mut self) {
        self.0.notify_waiters();
    }
}

impl NodeCoordinator {
    /// Assemble after explicit bootstrap/open, before starting listeners.
    pub fn new(store: NodeStore, clock: Arc<dyn Fn() -> UnixMillis + Send + Sync>) -> Self {
        Self {
            store: Arc::new(EndpointLock::new(store)),
            clock,
            changed: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Composition identity: two services must retain the same writer, not
    /// independently open the same authority journal.
    pub fn shares_writer(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.store, &other.store)
    }

    /// The bound provider enrollment, if any; it changes only through binding.
    pub async fn provider(
        &self,
    ) -> Result<Option<hellas_rpc::ProviderEnrollmentBundle>, NodeStoreError> {
        let (store, _) = self.lock().await?;
        Ok(store.state().provider().ok().cloned())
    }

    /// Validate a host's configured enrollment before attaching a service.
    pub async fn check_provider(
        &self,
        enrollment: &hellas_rpc::ProviderEnrollmentBundle,
    ) -> Result<(), NodeStoreError> {
        let (store, _) = self.lock().await?;
        if store.state().provider()? != enrollment {
            return Err(crate::model::grant::records::GrantError::Audience.into());
        }
        Ok(())
    }

    pub(crate) async fn writer(&self) -> Result<EndpointGuard<'_, NodeStore>, NodeStoreError> {
        self.store
            .lock()
            .await
            .map_err(|_| NodeStoreError::WriterPoisoned)
    }

    pub(crate) async fn lock(
        &self,
    ) -> Result<(EndpointGuard<'_, NodeStore>, UnixMillis), NodeStoreError> {
        let store = self.writer().await?;
        store.check_authority()?;
        let now = store.time((self.clock)())?;
        Ok((store, now))
    }

    /// Observe fresh time after a wait, including settlement of already-dispatched work.
    pub(crate) fn observed_time(&self, store: &NodeStore) -> UnixMillis {
        (self.clock)().max(store.state().now())
    }

    async fn checked<T>(
        &self,
        caller: &AuthenticatedCaller,
        authorization: GrantId,
        action: &'static str,
        operation: impl AsyncFnOnce(&mut NodeStore, UnixMillis) -> Result<T, NodeStoreError>,
    ) -> Result<T, NodeStoreError> {
        let mut decision =
            crate::audit::Decision::new(action, Some(authorization), Some(caller.credential()));
        let result = async {
            let (mut store, now) = self.lock().await?;
            decision.observe(store.state().authority(), Some(caller), now);
            operation(&mut store, now).await
        }
        .await;
        decision.finish(result)
    }

    /// Secret-only authentication; only `gateway.invoke` bearer credentials qualify.
    pub async fn authenticate(
        &self,
        secret: &CredentialSecret,
    ) -> Result<AuthenticatedCaller, NodeStoreError> {
        let mut decision =
            crate::audit::Decision::new("credential.authenticate", None, Some(secret.id()));
        let result = async {
            let (store, now) = self.lock().await?;
            let authority = store.state().authority();
            decision.observe(authority, None, now);
            let caller = authority.authenticate(secret, now)?;
            decision.observe(authority, Some(&caller), now);
            Ok(caller)
        }
        .await;
        decision.finish(result)
    }

    /// In-process authentication with exactly the proof a remote session needs.
    pub async fn authenticate_session(
        &self,
        secret: &CredentialSecret,
        key: SessionKey<'_>,
    ) -> Result<AuthenticatedCaller, NodeStoreError> {
        // No transport exists to bind; the challenge nonce keeps each proof fresh.
        let binding = Digest::hash(b"hellas.auth.in-process.v1");
        let pending = self.begin_authentication(binding).await?;
        let authority = pending.challenge().authority;
        let proof = key.prove(pending.challenge(), authority, binding, secret.id())?;
        Ok(self
            .complete_authentication(pending, binding, secret, &proof)
            .await?
            .into_caller())
    }

    /// Hosts must admit the connection and reserve its one pending slot first.
    pub async fn begin_authentication(
        &self,
        binding: Digest,
    ) -> Result<PendingAuthentication, NodeStoreError> {
        let (store, now) = self.lock().await?;
        Ok(store
            .state()
            .authority()
            .begin_authentication(binding, now)?)
    }

    pub async fn complete_authentication(
        &self,
        pending: PendingAuthentication,
        binding: Digest,
        secret: &CredentialSecret,
        proof: &SessionProof,
    ) -> Result<AuthenticatedSession, NodeStoreError> {
        let mut decision =
            crate::audit::Decision::new("session.authenticate", None, Some(secret.id()));
        let result = async {
            let (store, now) = self.lock().await?;
            let authority = store.state().authority();
            decision.observe(authority, None, now);
            let session = pending.complete(authority, binding, secret, proof, now)?;
            decision.observe(
                authority,
                session.authenticate(authority, binding, now).ok(),
                now,
            );
            Ok(session)
        }
        .await;
        decision.finish(result)
    }

    pub async fn session_caller<'a>(
        &self,
        session: &'a AuthenticatedSession,
        binding: Digest,
    ) -> Result<&'a AuthenticatedCaller, NodeStoreError> {
        let mut decision =
            crate::audit::Decision::new("session.validate", None, Some(session.credential()));
        let result = async {
            let (store, now) = self.lock().await?;
            let authority = store.state().authority();
            decision.observe(authority, None, now);
            let caller = session.authenticate(authority, binding, now)?;
            decision.observe(authority, Some(caller), now);
            Ok(caller)
        }
        .await;
        decision.finish(result)
    }

    /// Bounded, current administration metadata; never secret or verifier material.
    pub async fn inspect(
        &self,
        caller: &AuthenticatedCaller,
        authorization: GrantId,
        query: InspectionQuery,
    ) -> Result<AuthorityInspection, NodeStoreError> {
        self.checked(
            caller,
            authorization,
            "authority.inspect",
            async |store, now| {
                Ok(store
                    .state()
                    .authority()
                    .inspect(caller, authorization, &query, now)?)
            },
        )
        .await
    }

    pub async fn grant(
        &self,
        caller: &AuthenticatedCaller,
        command: GrantCommand,
    ) -> Result<AdministrationRecord, NodeStoreError> {
        let _changed = ChangeNotification(self.changed.clone());
        let (authorization, action) = match &command {
            GrantCommand::Issue { authorization, .. } => (*authorization, GRANT_ISSUE),
            GrantCommand::Delegate { parent, .. } => (*parent, "grant.delegate"),
            GrantCommand::Revise { authorization, .. } => (*authorization, "grant.revise"),
            GrantCommand::Revoke { authorization, .. } => (*authorization, GRANT_REVOKE),
        };
        self.checked(caller, authorization, action, async |store, now| {
            match &command {
                GrantCommand::Issue { spec, .. }
                | GrantCommand::Revise { spec, .. }
                | GrantCommand::Delegate { spec, .. } => validate_scope(store.state(), spec)?,
                GrantCommand::Revoke { .. } => {}
            }
            store
                .administer_authority(caller, AdministrationCommand::Grant(command), now)
                .await
        })
        .await
    }

    /// Commit a client-prepared verifier; the issuing client retains the secret.
    pub async fn issue_credential(
        &self,
        caller: &AuthenticatedCaller,
        authorization: GrantId,
        credential: Credential,
    ) -> Result<AdministrationRecord, NodeStoreError> {
        let _changed = ChangeNotification(self.changed.clone());
        self.checked(
            caller,
            authorization,
            CREDENTIAL_ISSUE,
            async |store, now| {
                validate_scope(store.state(), credential.scope())?;
                store
                    .administer_authority(
                        caller,
                        AdministrationCommand::Credential(CredentialCommand::Issue {
                            authorization,
                            credential: Box::new(credential),
                        }),
                        now,
                    )
                    .await
            },
        )
        .await
    }

    pub async fn revoke_credential(
        &self,
        caller: &AuthenticatedCaller,
        authorization: GrantId,
        id: CredentialId,
        expected: Revision,
    ) -> Result<AdministrationRecord, NodeStoreError> {
        let _changed = ChangeNotification(self.changed.clone());
        self.checked(
            caller,
            authorization,
            CREDENTIAL_REVOKE,
            async |store, now| {
                store
                    .administer_authority(
                        caller,
                        AdministrationCommand::Credential(CredentialCommand::Revoke {
                            authorization,
                            id,
                            expected,
                        }),
                        now,
                    )
                    .await
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests;
