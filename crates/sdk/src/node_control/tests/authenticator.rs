use super::*;
use hellas_work::authenticator::{Authenticator, PublicKey};
use std::sync::atomic::AtomicBool;

struct Prompt {
    key: hellas_kernel::SoftPasskey,
    entered: tokio::sync::Semaphore,
    approved: tokio::sync::Semaphore,
    dropped: Arc<AtomicBool>,
}
impl Prompt {
    fn new() -> Self {
        Self {
            key: ROOT.passkey(),
            entered: tokio::sync::Semaphore::new(0),
            approved: tokio::sync::Semaphore::new(0),
            dropped: Arc::new(AtomicBool::new(false)),
        }
    }
}
struct Pending(Arc<AtomicBool>);
impl Drop for Pending {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
#[async_trait::async_trait]
impl Authenticator for Prompt {
    fn public_key(&self) -> Result<PublicKey, AuthorityError> {
        self.key.public_key()
    }
    async fn assert(&self, challenge: Digest) -> Result<PasskeyAssertion, AuthorityError> {
        let _pending = Pending(self.dropped.clone());
        self.entered.add_permits(1);
        self.approved
            .acquire()
            .await
            .map_err(|_| AuthorityError::Credential)?
            .forget();
        self.key.assert(challenge).await
    }
}

#[cfg(unix)]
#[tokio::test]
async fn local_and_iroh_sessions_await_the_same_external_authenticator() {
    let f = fixture().await;
    let prompt = Prompt::new();
    let (server_config, client_config) = tls_configs();
    let socket = f.directory.path().join("prompt.sock");
    let listener = f.service.bind_local(&socket, server_config).unwrap();
    let local = connect_local(
        &socket,
        client_config,
        "localhost".try_into().unwrap(),
        authority(),
        &f.secret,
        SessionKey::Passkey(&prompt),
    );
    tokio::pin!(local);
    tokio::select! {
        result = &mut local => panic!("returned before owner approval: {:?}", result.err()),
        entered = prompt.entered.acquire() => entered.unwrap().forget(),
    }
    assert!(!prompt.dropped.load(Ordering::SeqCst));
    prompt.approved.add_permits(1);
    let (local, _) = local.await.unwrap();
    let local_status = local
        .get_host_status(read_request(ROOT_GRANT))
        .await
        .unwrap();

    let (_client_endpoint, _server_endpoint, outgoing, incoming) = pair().await;
    let closer = outgoing.clone();
    let task = serve(&f.service, incoming);
    let remote = connect_iroh(
        outgoing,
        authority(),
        &f.secret,
        SessionKey::Passkey(&prompt),
    );
    tokio::pin!(remote);
    tokio::select! {
        result = &mut remote => panic!("returned before owner approval: {:?}", result.err()),
        entered = prompt.entered.acquire() => entered.unwrap().forget(),
    }
    prompt.approved.add_permits(1);
    let (remote, _) = remote.await.unwrap();
    assert_eq!(
        local_status,
        remote
            .get_host_status(read_request(ROOT_GRANT))
            .await
            .unwrap()
    );
    closer.close(0u32.into(), b"test done");
    task.await.unwrap().unwrap_err();
    drop(local);
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn handshake_deadline_cancels_an_unanswered_authenticator_prompt() {
    let f = fixture().await;
    let prompt = Prompt::new();
    let (_client_endpoint, _server_endpoint, outgoing, incoming) = pair().await;
    let task = serve(&f.service, incoming);
    let connect = connect_iroh(
        outgoing,
        authority(),
        &f.secret,
        SessionKey::Passkey(&prompt),
    );
    tokio::pin!(connect);
    tokio::select! {
        result = &mut connect => panic!("returned before authenticator: {:?}", result.err()),
        entered = prompt.entered.acquire() => entered.unwrap().forget(),
    }
    assert!(!prompt.dropped.load(Ordering::SeqCst));
    let error = tokio::time::timeout(HANDSHAKE_TIMEOUT + Duration::from_secs(1), connect)
        .await
        .expect("existing handshake deadline is enforced")
        .err()
        .expect("unapproved session refused");
    assert_eq!(error.code(), WireCode::PermissionDenied);
    assert!(
        prompt.dropped.load(Ordering::SeqCst),
        "deadline dropped the actual prompt future"
    );
    task.await.unwrap().unwrap_err();
}
