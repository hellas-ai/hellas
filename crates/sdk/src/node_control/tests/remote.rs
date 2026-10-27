use super::*;
use hellas_authority::test_support::within;

struct Remote {
    fixture: Fixture,
    generation: u64,
    client: HostControlClientImpl<IrohTransport>,
    closer: Connection,
    task: tokio::task::JoinHandle<Result<(), WireStatus>>,
    endpoints: (Endpoint, Endpoint),
}
impl Remote {
    async fn new() -> Self {
        let fixture = fixture().await;
        let (client_endpoint, server_endpoint, outgoing, incoming) = pair().await;
        let closer = outgoing.clone();
        let task = serve(&fixture.service, incoming);
        let (client, challenge) = connect_iroh(
            outgoing,
            authority(),
            &fixture.secret,
            hellas_authority::node::SessionKey::Passkey(&ROOT.passkey()),
        )
        .await
        .unwrap();
        Self {
            fixture,
            generation: challenge.generation,
            client,
            closer,
            task,
            endpoints: (client_endpoint, server_endpoint),
        }
    }
    async fn native_status(&self) -> hellas_authority::node::NodeStatus {
        self.fixture
            .node
            .status(
                &hellas_authority::test_support::session(&self.fixture.node, &self.fixture.secret)
                    .await,
                ROOT_GRANT,
            )
            .await
            .unwrap()
    }
    async fn shutdown(self) {
        self.closer.close(0u32.into(), b"test completed");
        assert_eq!(
            within(self.task).await.unwrap().unwrap_err().code(),
            WireCode::Unavailable
        );
        self.endpoints.0.close().await;
        self.endpoints.1.close().await;
    }
}
fn reader_scope() -> GrantSpec {
    let mut spec = scope(OPERATOR);
    spec.issuance = None;
    spec.permissions
        .retain(|p| p.operation.as_str() == HOST_STATUS);
    spec
}

#[tokio::test]
async fn remote_status_matches_the_native_writer() {
    let remote = Remote::new().await;
    let native = remote.native_status().await;
    let status = remote
        .client
        .get_host_status(read_request(ROOT_GRANT))
        .await
        .unwrap();
    assert_eq!(status.authority, native.authority.0.as_bytes());
    assert_eq!(status.generation, native.generation);
    assert_eq!(status.authority_revision, native.authority_revision.0);
    assert!(status.provider_configured);
    assert_eq!(
        status.machine.unwrap().max_in_flight,
        u32::from(native.machine.unwrap().max_in_flight.get())
    );
    remote.shutdown().await;
}

#[tokio::test]
async fn omitted_capacity_limits_are_invalid_rpc_input() {
    let remote = Remote::new().await;
    let machine = remote.native_status().await.machine.unwrap();
    assert_eq!(
        remote
            .client
            .set_machine_capacity(SetMachineCapacityRequest {
                authorization: ROOT_GRANT.0.to_vec(),
                expected_revision: machine.revision.0,
                max_in_flight: 2,
                limits: vec![],
            })
            .await
            .unwrap_err()
            .code(),
        WireCode::InvalidArgument
    );
    remote.shutdown().await;
}

#[tokio::test]
async fn credential_frames_are_bounded_before_decoding() {
    let remote = Remote::new().await;
    for credential in [vec![], vec![0; MAX_COMMAND_BYTES + 1]] {
        assert_eq!(
            remote
                .client
                .issue_credential(IssueCredentialRequest {
                    authorization: ROOT_GRANT.0.to_vec(),
                    credential,
                })
                .await
                .unwrap_err()
                .code(),
            WireCode::InvalidArgument
        );
    }
    remote.shutdown().await;
}

#[tokio::test]
async fn client_prepared_credentials_round_trip_without_transmitting_the_secret() {
    use prost::Message;
    let remote = Remote::new().await;
    let (prepared, secret) =
        Credential::prepare(reader_scope(), OPERATOR.holder(), remote.generation).unwrap();
    let request = IssueCredentialRequest {
        authorization: ROOT_GRANT.0.to_vec(),
        credential: canonical_dag_cbor(&prepared).unwrap(),
    };
    let request_bytes = request.encode_to_vec();
    assert!(
        !request_bytes
            .windows(32)
            .any(|bytes| bytes == secret.expose_secret())
    );
    let reply = remote.client.issue_credential(request).await.unwrap();
    assert!(
        !reply
            .encode_to_vec()
            .windows(32)
            .any(|bytes| bytes == secret.expose_secret())
    );
    let caller = remote
        .fixture
        .node
        .authenticate_session(
            &secret,
            hellas_authority::node::SessionKey::Node(&OPERATOR.node_key()),
        )
        .await
        .unwrap();
    assert_eq!(caller.subject(), OPERATOR.principal());
    let record: AdministrationRecord = decode_dag_cbor(&reply.record).unwrap();
    assert_eq!(record.caller().actor(), ROOT.principal());
    assert_eq!(record.caller().credential(), remote.fixture.secret.id());
    assert!(
        matches!(record.command(), AdministrationCommand::Credential(CredentialCommand::Issue {
        authorization, credential,
    }) if *authorization == ROOT_GRANT && credential.as_ref() == &prepared)
    );
    remote.shutdown().await;
}

#[tokio::test]
async fn lost_credential_reply_is_reconciled_over_host_control() {
    let remote = Remote::new().await;
    let (prepared, retained) =
        Credential::prepare(reader_scope(), OPERATOR.holder(), remote.generation).unwrap();
    // A concurrent issuance has the identical scope and holder: scope matching
    // cannot identify which secret this client retained before submitting.
    let (other, _) =
        Credential::prepare(reader_scope(), OPERATOR.holder(), remote.generation).unwrap();
    for credential in [&prepared, &other] {
        drop(
            remote
                .client
                .issue_credential(IssueCredentialRequest {
                    authorization: ROOT_GRANT.0.to_vec(),
                    credential: canonical_dag_cbor(credential).unwrap(),
                })
                .await
                .unwrap(),
        );
    }
    let response = remote
        .client
        .inspect_authority(InspectAuthorityRequest {
            authorization: ROOT_GRANT.0.to_vec(),
            query: canonical_dag_cbor(&InspectionQuery::Credential { id: retained.id() }).unwrap(),
        })
        .await
        .unwrap();
    let inspection: AuthorityInspection = decode_dag_cbor(&response.reply).unwrap();
    let InspectionRecords::Credentials { records, next } = inspection.records else {
        panic!("credentials")
    };
    assert!(next.is_none());
    let [metadata]: [_; 1] = records.try_into().unwrap();
    assert_eq!(metadata.id, retained.id());
    assert_ne!(metadata.id, other.id());
    assert_eq!(&metadata.scope, prepared.scope());
    assert_eq!(metadata.holder, prepared.holder());
    assert_eq!(metadata.generation, remote.generation);
    assert_eq!(metadata.revision, Revision(1));
    assert!(!metadata.revoked);
    let json = serde_json::to_value(&metadata).unwrap();
    let keys: std::collections::BTreeSet<_> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        ["id", "scope", "holder", "generation", "revision", "revoked"].into()
    );
    remote
        .fixture
        .node
        .authenticate_session(
            &retained,
            hellas_authority::node::SessionKey::Node(&OPERATOR.node_key()),
        )
        .await
        .unwrap();
    // A stale revision is actionable only after authorization has succeeded.
    let request = |revision| RevokeCredentialRequest {
        authorization: ROOT_GRANT.0.to_vec(),
        credential_id: metadata.id.0.to_vec(),
        expected_revision: revision,
    };
    assert_eq!(
        remote
            .client
            .revoke_credential(request(999))
            .await
            .unwrap_err()
            .code(),
        WireCode::FailedPrecondition
    );
    remote
        .client
        .revoke_credential(request(metadata.revision.0))
        .await
        .unwrap();
    let response = remote
        .client
        .inspect_authority(InspectAuthorityRequest {
            authorization: ROOT_GRANT.0.to_vec(),
            query: canonical_dag_cbor(&InspectionQuery::Credential { id: metadata.id }).unwrap(),
        })
        .await
        .unwrap();
    let inspection: AuthorityInspection = decode_dag_cbor(&response.reply).unwrap();
    let InspectionRecords::Credentials { records, .. } = inspection.records else {
        panic!("credentials")
    };
    assert!(records[0].revoked);
    remote.shutdown().await;
}

fn maximal_scope() -> GrantSpec {
    let mut scope = reader_scope();
    let operations: std::collections::BTreeSet<_> = (0..hellas_auth::authority::MAX_PERMISSIONS)
        .map(|i| OperationId::new(format!("x{i:095}")).unwrap())
        .collect();
    let resources: std::collections::BTreeSet<_> = (0..hellas_auth::authority::MAX_PERMISSIONS)
        .map(|i| ResourceId(Digest::hash(&i.to_be_bytes())))
        .collect();
    scope.permissions = operations
        .iter()
        .cloned()
        .zip(resources.iter().copied())
        .map(|(operation, resource)| Permission {
            operation,
            resource,
        })
        .collect();
    scope.issuance = Some(IssuanceCeiling {
        operations,
        resources: CeilingResources::Named(resources),
        max_validity_ms: 1_000_000,
        max_delegation_depth: MAX_DELEGATION_DEPTH,
    });
    scope.not_before = UnixMillis(u64::MAX - 1);
    scope.expires = UnixMillis(u64::MAX);
    scope.delegation_depth = MAX_DELEGATION_DEPTH;
    scope.issuance.as_mut().unwrap().max_validity_ms = u64::MAX;
    Credential::prepare(scope.clone(), OPERATOR.holder(), 1).unwrap();
    scope
}

#[test]
fn maximal_credential_metadata_page_fits_the_bounded_wire_reply() {
    let scope = maximal_scope();
    let metadata = CredentialMetadata {
        id: CredentialId([255; 16]),
        scope,
        holder: OPERATOR.holder(),
        generation: u64::MAX,
        revision: Revision(u64::MAX),
        revoked: false,
    };
    let view = AuthorityInspection {
        authority: authority(),
        revision: Revision(u64::MAX),
        generation: u64::MAX,
        root_grant: ROOT_GRANT,
        records: InspectionRecords::Credentials {
            records: vec![metadata; INSPECTION_PAGE_SIZE],
            next: Some(CredentialId([255; 16])),
        },
    };
    encode_bounded(
        &view,
        hellas_authority::model::grant::admin::MAX_ADMIN_BYTES,
    )
    .unwrap();
}

#[test]
fn maximal_grant_pages_fit_the_bounded_wire_reply() {
    for origin in [
        GrantOrigin::Node {
            issuer: OPERATOR.principal(),
        },
        GrantOrigin::Delegated {
            parent: GrantId([255; 16]),
        },
    ] {
        let grant: Grant = serde_json::from_value(serde_json::json!({
            "id": GrantId([255; 16]), "revision": Revision(u64::MAX),
            "spec": maximal_scope(), "origin": origin, "revoked": false,
        }))
        .unwrap();
        let view = AuthorityInspection {
            authority: authority(),
            revision: Revision(u64::MAX),
            generation: u64::MAX,
            root_grant: ROOT_GRANT,
            records: InspectionRecords::Grants {
                records: vec![grant; INSPECTION_PAGE_SIZE],
                next: Some(GrantId([255; 16])),
            },
        };
        encode_bounded(
            &view,
            hellas_authority::model::grant::admin::MAX_ADMIN_BYTES,
        )
        .unwrap();
    }
}
