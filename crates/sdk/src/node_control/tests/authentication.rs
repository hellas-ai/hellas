use super::*;

async fn hello(connection: &Connection) -> (SendStream, RecvStream, SessionChallenge) {
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&[1]).await.unwrap();
    let length = usize::from(AsyncReadExt::read_u16(&mut recv).await.unwrap());
    assert!(length <= 256);
    let mut bytes = vec![0; length];
    recv.read_exact(&mut bytes).await.unwrap();
    (send, recv, decode_challenge(&bytes).unwrap())
}

#[tokio::test]
async fn authentication_rejects_prefix_only_oversize_replay_and_trailing_data_and_releases_slots() {
    let f = fixture().await;
    let (_ce, _se, cc, sc) = pair().await;
    let task = serve(&f.service, sc);
    let (mut send, _recv, first) = hello(&cc).await;
    let signature = first
        .sign_daily(
            authority(),
            binding(&IrohTransport::new(cc.clone())).unwrap(),
            f.secret.id(),
            &ROOT.node_key(),
        )
        .unwrap();
    let replay = encode_response(&f.secret, &signature).unwrap();
    // No body and no FIN: refusing this prefix proves it does not wait for or
    // allocate a peer-selected body before checking the authentication bound.
    let oversize =
        u16::try_from(hellas_rpc::authentication::MAX_AUTHENTICATION_MESSAGE_BYTES + 1).unwrap();
    AsyncWriteExt::write_u16(&mut send, oversize).await.unwrap();
    rejected(task).await;
    assert_eq!(
        f.service.remote_capacity.handshakes.available_permits(),
        MAX_CONNECTIONS
    );
    assert_eq!(
        f.service.remote_capacity.sessions.available_permits(),
        MAX_CONNECTIONS
    );
    for trailing in [false, true] {
        let (_ce, _se, cc, sc) = pair().await;
        let task = serve(&f.service, sc);
        let (mut send, _recv, challenge) = hello(&cc).await;
        let signature = challenge
            .sign_daily(
                authority(),
                binding(&IrohTransport::new(cc.clone())).unwrap(),
                f.secret.id(),
                &ROOT.node_key(),
            )
            .unwrap();
        let current = encode_response(&f.secret, &signature).unwrap();
        let response = if trailing { &current } else { &replay };
        AsyncWriteExt::write_u16(&mut send, response.len() as u16)
            .await
            .unwrap();
        send.write_all(response).await.unwrap();
        if trailing {
            send.write_all(&[7]).await.unwrap();
        }
        send.finish().unwrap();
        rejected(task).await;
    }
    let (_ce, _se, cc, sc) = pair().await;
    let task = serve(&f.service, sc);
    let (_send, mut recv, _) = hello(&cc).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    tokio::time::timeout(hellas_work::test_support::WAIT, recv.read(&mut [0]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(
        f.service.remote_capacity.handshakes.available_permits(),
        MAX_CONNECTIONS
    );
    assert_eq!(
        f.service.remote_capacity.sessions.available_permits(),
        MAX_CONNECTIONS
    );
    // Admission precedes challenge allocation and all rejected connections close.
    let held = f
        .service
        .remote_capacity
        .handshakes
        .acquire_many(MAX_CONNECTIONS as u32)
        .await
        .unwrap();
    let (_ce, _se, cc, sc) = pair().await;
    let task = serve(&f.service, sc);
    hellas_work::test_support::assert_err!(connect_iroh(cc, authority(), &f.secret, hellas_work::node::SessionKey::Passkey(&ROOT.passkey()))
            .await, status if status.code() == WireCode::PermissionDenied);
    assert_eq!(
        task.await.unwrap().unwrap_err().code,
        WireCode::ResourceExhausted
    );
    drop(held);
}
