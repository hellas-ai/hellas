use super::*;

#[cfg(unix)]
#[tokio::test]
async fn local_tls_requires_pinned_application_authentication() {
    let f = fixture().await;
    let (server_config, client_config) = tls_configs();
    hellas_private::restrict_directory(f.directory.path()).unwrap();
    let socket = f.directory.path().join("control.sock");
    // Each connection belongs to the same UID. That cannot authenticate an app.
    #[derive(Clone, Copy)]
    enum Attack {
        Pin,
        Audience,
        Identity,
        Alpn,
    }
    for bad in [
        Attack::Pin,
        Attack::Audience,
        Attack::Identity,
        Attack::Alpn,
    ] {
        let server_config = if matches!(bad, Attack::Pin) {
            tls_configs().0
        } else {
            server_config.clone()
        };
        let (server_config, client_config) = if matches!(bad, Attack::Alpn) {
            let mut server = (*server_config).clone();
            let mut client = (*client_config).clone();
            server.alpn_protocols = vec![b"/another/service/1".to_vec()];
            client.alpn_protocols = server.alpn_protocols.clone();
            (Arc::new(server), Arc::new(client))
        } else {
            (server_config, client_config.clone())
        };
        let listener = f.service.bind_local(&socket, server_config).unwrap();
        let expected = if matches!(bad, Attack::Audience) {
            AuthorityId(Digest::hash(b"another authority"))
        } else {
            authority()
        };
        let identity = if matches!(bad, Attack::Identity) {
            OPERATOR.passkey()
        } else {
            ROOT.passkey()
        };
        hellas_work::test_support::assert_err!(connect_local(
                &socket,
                client_config.clone(),
                "localhost".try_into().unwrap(),
                expected,
                &f.secret,
                hellas_work::node::SessionKey::Passkey(&identity),
            )
            .await, status if status.code() == WireCode::PermissionDenied);
        listener.shutdown().await.unwrap();
        assert!(!socket.exists());
        assert_eq!(f.service.local_slots.available_permits(), MAX_CONNECTIONS);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn local_control_matches_remote_authority_decisions() {
    let f = fixture().await;
    let (server_config, client_config) = tls_configs();
    let socket = f.directory.path().join("control.sock");
    let listener = f.service.bind_local(&socket, server_config).unwrap();
    let (local, _) = connect_local(
        &socket,
        client_config,
        "localhost".try_into().unwrap(),
        authority(),
        &f.secret,
        hellas_work::node::SessionKey::Passkey(&ROOT.passkey()),
    )
    .await
    .unwrap();
    let (_ce, _se, cc, sc) = pair().await;
    let closer = cc.clone();
    let remote_task = serve(&f.service, sc);
    let (remote, _) = connect_iroh(
        cc,
        authority(),
        &f.secret,
        hellas_work::node::SessionKey::Passkey(&ROOT.passkey()),
    )
    .await
    .unwrap();
    assert_eq!(
        local
            .get_host_status(read_request(ROOT_GRANT))
            .await
            .unwrap(),
        remote
            .get_host_status(read_request(ROOT_GRANT))
            .await
            .unwrap()
    );
    let limits = vec![Limit {
        meter: Meter::InputTokens,
        window: Window::Hour,
        amount: 500,
    }];
    local
        .set_machine_capacity(SetMachineCapacityRequest {
            limits: canonical_dag_cbor(&limits).unwrap(),
            authorization: ROOT_GRANT.0.to_vec(),
            expected_revision: 1,
            max_in_flight: 3,
        })
        .await
        .unwrap();
    let remote_machine = remote
        .get_host_status(read_request(ROOT_GRANT))
        .await
        .unwrap()
        .machine
        .unwrap();
    assert_eq!(remote_machine.max_in_flight, 3);
    assert_eq!(
        decode_dag_cbor::<Vec<Limit>>(&remote_machine.limits).unwrap(),
        limits
    );
    let mut spec = scope(OPERATOR);
    spec.issuance = None;
    spec.permissions
        .retain(|p| p.operation.as_str() == HOST_STATUS);
    local
        .grant_control(GrantControlRequest {
            command: canonical_dag_cbor(&GrantCommand::Issue {
                authorization: ROOT_GRANT,
                id: GrantId([2; 16]),
                spec: spec.clone(),
            })
            .unwrap(),
        })
        .await
        .unwrap();
    let (prepared, secret) = Credential::prepare(spec, OPERATOR.holder(), 1).unwrap();
    local
        .issue_credential(IssueCredentialRequest {
            authorization: ROOT_GRANT.0.to_vec(),
            credential: canonical_dag_cbor(&prepared).unwrap(),
        })
        .await
        .unwrap();
    f.node
        .status(
            &f.node
                .authenticate_session(
                    &secret,
                    hellas_work::node::SessionKey::Node(&OPERATOR.node_key()),
                )
                .await
                .unwrap(),
            GrantId([2; 16]),
        )
        .await
        .unwrap();
    remote
        .revoke_credential(RevokeCredentialRequest {
            authorization: ROOT_GRANT.0.to_vec(),
            credential_id: secret.id().0.to_vec(),
            expected_revision: 1,
        })
        .await
        .unwrap();
    hellas_work::test_support::assert_err!(
        f.node.authenticate(&secret).await,
        NodeStoreError::Authority(AuthorityError::Credential)
    );

    tokio::time::timeout(hellas_work::test_support::WAIT, listener.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(!socket.exists());
    hellas_work::test_support::assert_err!(local
            .get_host_status(read_request(ROOT_GRANT))
            .await, status if matches!(status.code(), WireCode::Unavailable | WireCode::Internal));
    closer.close(0u32.into(), b"test completed");
    hellas_work::test_support::assert_err!(tokio::time::timeout(hellas_work::test_support::WAIT, remote_task)
            .await
            .unwrap()
            .unwrap(), status if status.code() == WireCode::Unavailable);
    assert_eq!(f.service.local_slots.available_permits(), MAX_CONNECTIONS);
}

#[cfg(unix)]
#[tokio::test]
async fn local_listener_bounds_authentication_and_joins_connections_without_removing_other_paths() {
    use std::os::unix::fs::PermissionsExt;
    let f = fixture().await;
    let (server_config, client_config) = tls_configs();
    let parent = f.directory.path().join("listener");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    let socket = parent.join("control.sock");
    assert_eq!(
        f.service
            .bind_local(&socket, server_config.clone())
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert!(!socket.exists());
    hellas_private::restrict_directory(&parent).unwrap();
    std::fs::write(&socket, b"existing file").unwrap();
    hellas_work::test_support::assert_err!(f.service
            .bind_local(&socket, server_config.clone()), error if error.kind() == std::io::ErrorKind::AddrInUse);
    assert_eq!(std::fs::read(&socket).unwrap(), b"existing file");
    std::fs::remove_file(&socket).unwrap();

    let listener = f
        .service
        .bind_local(&socket, server_config.clone())
        .unwrap();
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    hellas_work::test_support::assert_err!(f.service
            .bind_local(&socket, server_config.clone()), error if error.kind() == std::io::ErrorKind::AddrInUse);
    let wait_slots = async |expected| {
        tokio::time::timeout(hellas_work::test_support::WAIT, async {
            while f.service.local_slots.available_permits() != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    };
    // Raw peers consume admission while TLS is unfinished. They do not reach
    // RPC or create authority; remote QUIC retains independent capacity.
    let mut pending = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        pending.push(hellas_wire::local::connect_stream(&socket).await.unwrap());
    }
    wait_slots(0).await;
    let mut extra = hellas_wire::local::connect_stream(&socket).await.unwrap();
    assert_eq!(
        tokio::time::timeout(hellas_work::test_support::WAIT, extra.read_u8())
            .await
            .unwrap()
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    let (_ce, _se, cc, sc) = pair().await;
    let remote_task = serve(&f.service, sc);
    let closer = cc.clone();
    let (remote, _) = connect_iroh(
        cc,
        authority(),
        &f.secret,
        hellas_work::node::SessionKey::Passkey(&ROOT.passkey()),
    )
    .await
    .unwrap();
    remote
        .get_host_status(read_request(ROOT_GRANT))
        .await
        .unwrap();
    let held_remote = f
        .service
        .remote_capacity
        .sessions
        .acquire_many((MAX_CONNECTIONS - 1) as u32)
        .await
        .unwrap();
    drop(pending.pop());
    wait_slots(1).await;
    let (local, _) = connect_local(
        &socket,
        client_config,
        "localhost".try_into().unwrap(),
        authority(),
        &f.secret,
        hellas_work::node::SessionKey::Passkey(&ROOT.passkey()),
    )
    .await
    .unwrap();
    local
        .get_host_status(read_request(ROOT_GRANT))
        .await
        .unwrap();
    wait_slots(0).await;
    drop(held_remote);
    closer.close(0u32.into(), b"fixture complete");
    remote_task.await.unwrap().unwrap_err();

    // Shutdown joins both incomplete TLS handshakes and the authenticated mux.
    // If someone replaced the socket path, cleanup must preserve their file.
    std::fs::remove_file(&socket).unwrap();
    std::fs::write(&socket, b"replacement").unwrap();
    tokio::time::timeout(hellas_work::test_support::WAIT, listener.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(f.service.local_slots.available_permits(), MAX_CONNECTIONS);
    hellas_work::test_support::assert_err!(local
            .get_host_status(read_request(ROOT_GRANT))
            .await, status if matches!(status.code(), WireCode::Unavailable | WireCode::Internal));
    assert_eq!(std::fs::read(&socket).unwrap(), b"replacement");
    for stream in &mut pending {
        stream.read_u8().await.unwrap_err();
    }
    std::fs::remove_file(&socket).unwrap();

    // Cancellation still aborts ownership; explicit shutdown above is the
    // barrier hosts use before draining/reopening the writer.
    let listener = f.service.bind_local(&socket, server_config).unwrap();
    let mut pending = hellas_wire::local::connect_stream(&socket).await.unwrap();
    wait_slots(MAX_CONNECTIONS - 1).await;
    drop(listener);
    tokio::time::timeout(hellas_work::test_support::WAIT, pending.read_u8())
        .await
        .unwrap()
        .unwrap_err();
    wait_slots(MAX_CONNECTIONS).await;
    assert!(!socket.exists());
}

#[tokio::test]
async fn tls_twelve_is_refused_before_application_authentication() {
    let f = fixture().await;
    let (server_config, client_config) = tls_configs_with_versions(&[&rustls::version::TLS12]);
    let (client, server) = tokio::io::duplex(8192);
    let service = f.service.clone();
    let task = tokio::spawn(async move { service.serve_tls(server, server_config).await });
    let mut client = tokio_rustls::TlsConnector::from(client_config)
        .connect("localhost".try_into().unwrap(), client)
        .await
        .unwrap();
    assert_eq!(
        client.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2)
    );
    // A TLS-only refusal closes before even allocating an application challenge.
    // Without this read, the authentication timeout could satisfy the same error assertion.
    let challenge = hellas_work::test_support::within(async {
        client.write_all(&[1]).await?;
        client.flush().await?;
        client.read_u8().await
    })
    .await;
    hellas_work::test_support::assert_err!(challenge,
        error if matches!(error.kind(), std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::BrokenPipe));
    assert_eq!(
        hellas_work::test_support::within(task)
            .await
            .unwrap()
            .unwrap_err()
            .code(),
        WireCode::PermissionDenied
    );
    assert_eq!(f.service.local_slots.available_permits(), MAX_CONNECTIONS);
}

#[cfg(unix)]
#[tokio::test]
async fn same_uid_with_pinned_tls_but_no_credential_cannot_dispatch_an_operation() {
    let f = fixture().await;
    let (server_config, client_config) = tls_configs();
    let socket = f.directory.path().join("no-credential.sock");
    let listener = f.service.bind_local(&socket, server_config).unwrap();
    let stream = hellas_wire::local::connect_stream(&socket).await.unwrap();
    let (stream, context) = hellas_wire::tls::connect(
        stream,
        client_config,
        "localhost".try_into().unwrap(),
        HostControl::ALPN.as_bytes(),
    )
    .await
    .unwrap();
    // This process has the right UID and server pin, but deliberately skips
    // application authentication and sends an actual typed operation.
    let transport =
        hellas_wire::local::transport(stream, hellas_wire::mux::Role::Client, context).unwrap();
    let client = HostControlClientImpl::new(transport);
    assert!(
        hellas_work::test_support::within(client.get_host_status(read_request(ROOT_GRANT)))
            .await
            .is_err()
    );
    listener.shutdown().await.unwrap();
    assert_eq!(f.service.local_slots.available_permits(), MAX_CONNECTIONS);
}
