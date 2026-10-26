use super::*;

async fn apply(client: &Client, commands: &[CredentialCommand]) {
    for command in commands {
        match command {
            CredentialCommand::Issue {
                authorization,
                credential,
            } => {
                client
                    .issue_credential(IssueCredentialRequest {
                        authorization: authorization.0.to_vec(),
                        credential: canonical_dag_cbor(credential).unwrap(),
                    })
                    .await
                    .unwrap();
            }
            CredentialCommand::Revoke {
                authorization,
                id,
                expected,
            } => {
                client
                    .revoke_credential(RevokeCredentialRequest {
                        authorization: authorization.0.to_vec(),
                        credential_id: id.0.to_vec(),
                        expected_revision: expected.0,
                    })
                    .await
                    .unwrap();
            }
        }
    }
}

async fn admitted(address: &str, bearer: Option<&str>) -> reqwest::StatusCode {
    // Admission runs before method dispatch: an admitted GET gets 405 without
    // spending an unrelated upstream allowance on every credential check.
    let request = reqwest::Client::new().get(format!("{address}/v1/responses"));
    let request = match bearer {
        Some(bearer) => request.bearer_auth(bearer),
        None => request,
    };
    let response = request.send().await.unwrap();
    let status = response.status();
    response.bytes().await.unwrap();
    status
}

// The declarative caller compiles its document to the same authority commands
// as interactive issuance. Only verifiers cross HostControl in either case.
async fn multi_key_lifecycle(declarative: bool) {
    let world = crate::test_support::Host::builder().build().await;
    let (host, client, _, remote) = gateway_host(&world).await;
    client.set_gateway_state(gateway_state(true)).await.unwrap();
    let access = client.get_gateway_access(access_request()).await.unwrap();
    let scope = hellas_work::test_support::Rights::new(authority(), ROOT)
        .allow(
            hellas_work::node::GATEWAY_INVOKE,
            host_resource(authority()),
        )
        .valid_from(world.world.clock.now())
        .valid_until(UnixMillis(u64::MAX))
        .build();
    let mut commands = Vec::new();
    let mut secrets = Vec::new();
    for _ in 0..3 {
        let (credential, secret) =
            Credential::prepare(scope.clone(), CredentialHolder::Bearer, 1).unwrap();
        commands.push(CredentialCommand::Issue {
            authorization: ROOT_GRANT,
            credential: Box::new(credential),
        });
        secrets.push(secret);
    }
    if declarative {
        let document = serde_json::to_vec(&commands).unwrap();
        let decoded: Vec<CredentialCommand> = serde_json::from_slice(&document).unwrap();
        apply(&client, &decoded).await;
    } else {
        for command in &commands {
            apply(&client, std::slice::from_ref(command)).await;
        }
    }
    let bearers: Vec<_> = secrets
        .iter()
        .map(|secret| {
            format!(
                "{}{}",
                secret.id(),
                hellas_rpc::provenance::encode_hex(secret.expose_secret())
            )
        })
        .collect();
    assert_eq!(
        admitted(&access.address, None).await,
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        admitted(&access.address, Some(&"00".repeat(48))).await,
        reqwest::StatusCode::UNAUTHORIZED
    );
    for bearer in &bearers {
        assert_eq!(
            admitted(&access.address, Some(bearer)).await,
            reqwest::StatusCode::METHOD_NOT_ALLOWED
        );
    }
    // Rotate key 0 by issuing key 2 before revoking it; revoke key 1
    // independently. Neither operation replaces the listener's access object.
    let revocations: Vec<_> = secrets[..2]
        .iter()
        .map(|secret| CredentialCommand::Revoke {
            authorization: ROOT_GRANT,
            id: secret.id(),
            expected: Revision(1),
        })
        .collect();
    if declarative {
        let document = serde_json::to_vec(&revocations).unwrap();
        apply(
            &client,
            &serde_json::from_slice::<Vec<CredentialCommand>>(&document).unwrap(),
        )
        .await;
    } else {
        for command in &revocations {
            apply(&client, std::slice::from_ref(command)).await;
        }
    }
    for (index, bearer) in bearers.iter().enumerate() {
        assert_eq!(
            admitted(&access.address, Some(bearer)).await,
            if index < 2 {
                reqwest::StatusCode::UNAUTHORIZED
            } else {
                reqwest::StatusCode::METHOD_NOT_ALLOWED
            }
        );
        let reply = client
            .inspect_authority(InspectAuthorityRequest {
                authorization: ROOT_GRANT.0.to_vec(),
                query: canonical_dag_cbor(&InspectionQuery::Credential {
                    id: secrets[index].id(),
                })
                .unwrap(),
            })
            .await
            .unwrap();
        let metadata: AuthorityInspection = decode_dag_cbor(&reply.reply).unwrap();
        let InspectionRecords::Credentials { records, .. } = metadata.records else {
            panic!("credential metadata")
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].revoked, index < 2);
    }
    let still_running = client.get_gateway_access(access_request()).await.unwrap();
    assert_eq!(still_running, access);
    assert_eq!(
        admitted(&access.address, Some(&access.bearer)).await,
        reqwest::StatusCode::METHOD_NOT_ALLOWED
    );
    host.shutdown().await.unwrap();
    remote.shutdown().await;
}

#[tokio::test]
async fn running_gateway_supports_independent_dynamic_keys() {
    multi_key_lifecycle(false).await;
}

#[tokio::test]
async fn running_gateway_supports_declarative_key_commands() {
    multi_key_lifecycle(true).await;
}
