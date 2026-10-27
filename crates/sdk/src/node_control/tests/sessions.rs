use super::*;
use hellas_authority::test_support::{credentials, ids, within};

struct Reader {
    fixture: Fixture,
    credential: CredentialSecret,
    grant_revision: Revision,
    client: HostControlClientImpl<IrohTransport>,
    task: tokio::task::JoinHandle<Result<(), WireStatus>>,
    closer: Connection,
    endpoints: (Endpoint, Endpoint),
}
impl Reader {
    async fn new() -> Self {
        let fixture = fixture().await;
        let root = hellas_authority::test_support::session(&fixture.node, &fixture.secret).await;
        let mut rights = scope(OPERATOR);
        rights.issuance = None;
        rights
            .permissions
            .retain(|p| p.operation.as_str() == HOST_STATUS);
        let issued = fixture
            .node
            .grant(
                &root,
                GrantCommand::Issue {
                    authorization: ROOT_GRANT,
                    id: ids::OPERATOR_GRANT,
                    spec: rights.clone(),
                },
            )
            .await
            .unwrap();
        let [credential] = credentials::issue(
            credentials::Issuer::Node(&fixture.node),
            &root,
            ROOT_GRANT,
            None,
            rights,
        )
        .await;
        let (ce, se, outgoing, incoming) = pair().await;
        let closer = outgoing.clone();
        let task = serve(&fixture.service, incoming);
        let (client, _) = connect_iroh(
            outgoing,
            authority(),
            &credential,
            hellas_authority::node::SessionKey::Passkey(&OPERATOR.passkey()),
        )
        .await
        .unwrap();
        client
            .get_host_status(read_request(ids::OPERATOR_GRANT))
            .await
            .unwrap();
        Self {
            fixture,
            credential,
            grant_revision: issued.revision(),
            client,
            task,
            closer,
            endpoints: (ce, se),
        }
    }
    async fn finish(self) {
        self.closer.close(0u32.into(), b"test completed");
        within(self.task).await.unwrap().unwrap_err();
        self.endpoints.0.close().await;
        self.endpoints.1.close().await;
    }
}

#[tokio::test]
async fn a_live_connection_rechecks_its_selected_grant() {
    let reader = Reader::new().await;
    let root =
        hellas_authority::test_support::session(&reader.fixture.node, &reader.fixture.secret).await;
    reader
        .fixture
        .node
        .grant(
            &root,
            GrantCommand::Revoke {
                authorization: ROOT_GRANT,
                id: ids::OPERATOR_GRANT,
                expected: reader.grant_revision,
            },
        )
        .await
        .unwrap();
    let revoked = reader
        .client
        .get_host_status(read_request(ids::OPERATOR_GRANT))
        .await
        .unwrap_err();
    let unknown = reader
        .client
        .get_host_status(read_request(ids::MISSING))
        .await
        .unwrap_err();
    assert_eq!(revoked.code(), WireCode::PermissionDenied);
    assert_eq!(unknown.code(), revoked.code());
    assert_eq!(unknown.message, revoked.message);
    reader.finish().await;
}

#[tokio::test]
async fn a_live_connection_rechecks_its_credential_before_decoding_rpc() {
    let reader = Reader::new().await;
    let (_ce, _se, outgoing, incoming) = pair().await;
    let admin_task = serve(&reader.fixture.service, incoming);
    let closer = outgoing.clone();
    let (admin, _) = connect_iroh(
        outgoing,
        authority(),
        &reader.fixture.secret,
        hellas_authority::node::SessionKey::Passkey(&ROOT.passkey()),
    )
    .await
    .unwrap();
    let revoked = admin
        .revoke_credential(RevokeCredentialRequest {
            authorization: ROOT_GRANT.0.to_vec(),
            credential_id: reader.credential.id().0.to_vec(),
            expected_revision: 1,
        })
        .await
        .unwrap();
    let record: AdministrationRecord = decode_dag_cbor(&revoked.record).unwrap();
    assert!(
        matches!(record.command(), AdministrationCommand::Credential(CredentialCommand::Revoke { id, .. }) if *id == reader.credential.id())
    );
    reader
        .client
        .get_host_status(read_request(ids::OPERATOR_GRANT))
        .await
        .unwrap_err();
    assert_eq!(
        within(reader.task).await.unwrap().unwrap_err().code(),
        WireCode::PermissionDenied
    );
    closer.close(0u32.into(), b"test completed");
    within(admin_task).await.unwrap().unwrap_err();
    reader.endpoints.0.close().await;
    reader.endpoints.1.close().await;
}
