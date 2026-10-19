//! Connection-bound identity authentication. Hosts keep at most one pending
//! challenge per admitted connection and discard challenges/sessions on close.
//! Neither value is persistable, clonable or accepted from the peer.

use super::*;
use crate::{
    Digest, ProducerSigningKey, Signature, hash_tuple, signature::verify_digest_signature,
};

pub const MAX_CHALLENGE_LIFETIME_MS: u64 = 60_000;
pub const MAX_SESSION_LIFETIME_MS: u64 = 15 * 60_000;

/// Public challenge data, not proof that the server issued a challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionChallenge {
    pub authority: AuthorityId,
    pub generation: u64,
    pub nonce: [u8; 32],
    pub binding: Digest,
    pub issued_at: UnixMillis,
    pub deadline: UnixMillis,
    pub session_expires: UnixMillis,
}

impl SessionChallenge {
    /// Structural validation for codecs; authentication also checks live time,
    /// authority generation and an independently obtained transport binding.
    pub fn validate(&self) -> Result<(), AuthorityError> {
        let challenge_lifetime = self.deadline.0.checked_sub(self.issued_at.0);
        let session_lifetime = self.session_expires.0.checked_sub(self.issued_at.0);
        if self.generation == 0
            || !challenge_lifetime.is_some_and(|n| n > 0 && n <= MAX_CHALLENGE_LIFETIME_MS)
            || !session_lifetime.is_some_and(|n| n > 0 && n <= MAX_SESSION_LIFETIME_MS)
            || self.deadline > self.session_expires
        {
            return Err(AuthorityError::Credential);
        }
        Ok(())
    }

    /// Sign only after authenticating the expected server. `binding` must come
    /// from this connection, never from the challenge or another peer's request.
    /// A signature alone confers no grant or application credential rights.
    pub fn sign(
        &self,
        authority: AuthorityId,
        binding: Digest,
        credential: CredentialId,
        key: &ProducerSigningKey,
    ) -> Result<Signature, AuthorityError> {
        // Time is the server's to enforce: a client whose clock trails the
        // server's must still be able to answer a fresh challenge.
        self.validate()?;
        if self.authority != authority || self.binding != binding {
            return Err(AuthorityError::Credential);
        }
        let subject = PrincipalId::from_public_key(key.public_key())?;
        key.sign_digest(self.digest(credential, subject))
            .map_err(|_| AuthorityError::Credential)
    }

    fn check(
        &self,
        authority: AuthorityId,
        binding: Digest,
        now: UnixMillis,
    ) -> Result<(), AuthorityError> {
        self.validate()?;
        if self.authority != authority
            || self.binding != binding
            || now < self.issued_at
            || now >= self.deadline
        {
            return Err(AuthorityError::Credential);
        }
        Ok(())
    }

    fn digest(&self, credential: CredentialId, subject: PrincipalId) -> Digest {
        hash_tuple(
            "hellas.auth.session.proof.v1",
            &[
                self.authority.0.as_bytes(),
                &self.generation.to_be_bytes(),
                &self.nonce,
                self.binding.as_bytes(),
                &self.issued_at.0.to_be_bytes(),
                &self.deadline.0.to_be_bytes(),
                &self.session_expires.0.to_be_bytes(),
                &credential.0,
                subject.as_bytes(),
            ],
        )
    }
}

/// One server-issued challenge. Completing consumes it, including on failure.
/// An adapter must take it from its connection slot before processing a response.
pub struct PendingAuthentication {
    challenge: SessionChallenge,
}

impl PendingAuthentication {
    pub fn challenge(&self) -> &SessionChallenge {
        &self.challenge
    }

    pub fn complete(
        self,
        authority: &AuthorityState,
        binding: Digest,
        credential: &CredentialSecret,
        signature: &Signature,
        now: UnixMillis,
    ) -> Result<AuthenticatedSession, AuthorityError> {
        self.challenge.check(authority.authority(), binding, now)?;
        if self.challenge.generation != authority.generation() {
            return Err(AuthorityError::Credential);
        }
        let mut caller = authority.authenticate_secret(credential, now)?;
        verify_digest_signature(
            &caller.subject.public_key(),
            signature,
            self.challenge.digest(credential.id(), caller.subject),
        )
        .map_err(|_| AuthorityError::Credential)?;
        caller.expires = caller.expires.min(self.challenge.session_expires);
        Ok(AuthenticatedSession { caller, binding })
    }
}

/// Private connection state, never a client-supplied session ID or permit.
pub struct AuthenticatedSession {
    caller: AuthenticatedCaller,
    binding: Digest,
}

impl AuthenticatedSession {
    /// An audit locator only; callers must still revalidate this session.
    pub fn credential(&self) -> CredentialId {
        self.caller.credential()
    }

    /// Revalidate on the exact transport before handing evidence to a service.
    /// The service must still authorize against its current grant state under
    /// the coordinator lock, including after asynchronous work or durable writes.
    pub fn authenticate<'a>(
        &'a self,
        authority: &AuthorityState,
        binding: Digest,
        now: UnixMillis,
    ) -> Result<&'a AuthenticatedCaller, AuthorityError> {
        if binding != self.binding {
            return Err(AuthorityError::Credential);
        }
        authority.check_caller(&self.caller, now)?;
        Ok(&self.caller)
    }

    pub const fn expires(&self) -> UnixMillis {
        self.caller.expires
    }

    /// For an in-process session, whose binding names no transport to recheck.
    pub fn into_caller(self) -> AuthenticatedCaller {
        self.caller
    }
}

impl AuthorityState {
    /// Called only after host connection admission. The binding is trusted
    /// transport context, not a peer identity or a request field.
    pub fn begin_authentication(
        &self,
        binding: Digest,
        now: UnixMillis,
    ) -> Result<PendingAuthentication, AuthorityError> {
        if now < self.now() {
            return Err(AuthorityError::Clock);
        }
        let deadline = now.0.checked_add(MAX_CHALLENGE_LIFETIME_MS);
        let session_expires = now.0.checked_add(MAX_SESSION_LIFETIME_MS);
        let (Some(deadline), Some(session_expires)) = (deadline, session_expires) else {
            return Err(AuthorityError::Capacity);
        };
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| AuthorityError::Entropy)?;
        Ok(PendingAuthentication {
            challenge: SessionChallenge {
                authority: self.authority(),
                generation: self.generation(),
                nonce,
                binding,
                issued_at: now,
                deadline: UnixMillis(deadline),
                session_expires: UnixMillis(session_expires),
            },
        })
    }
}
