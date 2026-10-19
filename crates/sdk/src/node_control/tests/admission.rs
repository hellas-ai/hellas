use super::*;

#[tokio::test]
async fn handshake_hook_rejects_unlisted_endpoints_before_control_admission() {
    let f = fixture().await;
    let admission = f.service.remote_admission.clone();
    assert!(!RemoteControlAdmission::default().enabled());
    hellas_work::test_support::assert_err!(RemoteControlAdmission::new(vec![SecretKey::from_bytes(&[62; 32]).public(); 2]), status if status.code() == WireCode::InvalidArgument);
    let server = Endpoint::builder(presets::Minimal)
        .hooks(admission)
        .alpns(vec![HostControl::ALPN.as_bytes().to_vec()])
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let target = EndpointAddr::from_parts(
        server.id(),
        server.bound_sockets().into_iter().map(TransportAddr::Ip),
    );
    for seed in [63, 62] {
        let client = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[seed; 32]))
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let (client_connection, accepted) = tokio::join!(
            client.connect(target.clone(), HostControl::ALPN.as_bytes()),
            async { server.accept().await.unwrap().accept().unwrap().await }
        );
        if seed == 63 {
            accepted.unwrap_err();
            if let Ok(connection) = client_connection {
                tokio::time::timeout(hellas_work::test_support::WAIT, connection.closed())
                    .await
                    .unwrap();
            }
        } else {
            let task = serve(&f.service, accepted.unwrap());
            // Endpoint admission alone never grants application authority.
            hellas_work::test_support::assert_err!(connect_iroh(
                    client_connection.unwrap(),
                    authority(),
                    &f.secret,
                    hellas_work::node::SessionKey::Passkey(&OPERATOR.passkey())
                )
                .await, status if status.code() == WireCode::PermissionDenied);
            rejected(task).await;
        }
        assert_eq!(f.service.remote_slots.available_permits(), MAX_CONNECTIONS);
        client.close().await;
    }
    server.close().await;
}

#[tokio::test]
async fn incomplete_authentication_releases_control_capacity_at_its_deadline() {
    let f = fixture().await;
    let (server_config, _client_config) = tls_configs();
    let (_pending, stream) = tokio::io::duplex(8192);
    let service = f.service.clone();
    let config = server_config.clone();
    let pending = tokio::spawn(async move { service.serve_tls(stream, config).await });
    tokio::time::pause();
    tokio::task::yield_now().await;
    assert_eq!(
        f.service.local_slots.available_permits(),
        MAX_CONNECTIONS - 1
    );
    tokio::time::advance(HANDSHAKE_TIMEOUT).await;
    hellas_work::test_support::assert_err!(pending.await.unwrap(), status if status.code() == WireCode::PermissionDenied);
    assert_eq!(f.service.local_slots.available_permits(), MAX_CONNECTIONS);
    tokio::time::resume();
}

#[tokio::test]
async fn idle_sessions_release_control_capacity() {
    let f = fixture().await;
    let (server_config, client_config) = tls_configs();
    let (client, server) = tokio::io::duplex(8192);
    let service = f.service.clone();
    let task = tokio::spawn(async move { service.serve_tls(server, server_config).await });
    let client = connect_tls(
        client,
        client_config,
        "localhost".try_into().unwrap(),
        authority(),
        &f.secret,
        hellas_work::node::SessionKey::Passkey(&ROOT.passkey()),
    )
    .await
    .unwrap();
    client
        .get_host_status(read_request(ROOT_GRANT))
        .await
        .unwrap();
    tokio::time::pause();
    tokio::time::advance(IDLE_TIMEOUT + Duration::from_secs(1)).await;
    hellas_work::test_support::assert_err!(task.await.unwrap(), status if status.code() == WireCode::PermissionDenied);
    assert_eq!(f.service.local_slots.available_permits(), MAX_CONNECTIONS);
    hellas_work::test_support::assert_err!(client
            .get_host_status(read_request(ROOT_GRANT))
            .await, status if matches!(status.code(), WireCode::Unavailable | WireCode::Internal));
}
