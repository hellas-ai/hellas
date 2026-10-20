use super::*;
use axum::{Router, routing::get};
use hellas_auth::{Digest, authority::*};
use hellas_work::{
    node::{GATEWAY_INVOKE, host_resource},
    test_support::{Rights, TestClock, actors::ROOT, assert_err, common_node, ids::ROOT_GRANT},
    work_store::grant::NodeStore,
};
use tower::ServiceExt;

const HTTP_ACCESS: GrantId = GrantId([104; 16]);

pub(crate) struct Fixture {
    pub(crate) root: tempfile::TempDir,
    pub(crate) access: GatewayAccess,
    admin: CredentialSecret,
    clock: TestClock,
    grant_revision: Revision,
}
impl Fixture {
    pub(crate) async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let authority = AuthorityId(Digest::hash(b"HTTP gateway authority"));
        let subject = ROOT.principal();
        let now = UnixMillis(1000);
        let administrator = common_node::admin_spec(
            authority,
            subject,
            &[(GATEWAY_INVOKE, host_resource(authority))],
            (now, UnixMillis(100_000)),
            (99_000, 0),
            &[],
        );
        let (store, admin) = NodeStore::bootstrap(
            root.path(),
            hellas_work::model::grant::grant_network(),
            ROOT_GRANT,
            hellas_work::test_support::common_node::approval_for(
                hellas_auth::authority::Ownership::Bootstrap { root: ROOT_GRANT },
                administrator.clone(),
                administrator,
            ),
            None,
            now,
        )
        .await
        .unwrap();
        let clock = TestClock::new(now);
        let node = NodeCoordinator::new(store, clock.source());
        let caller = hellas_work::test_support::session(&node, &admin).await;
        let scope = Rights::new(authority, ROOT)
            .allow(GATEWAY_INVOKE, host_resource(authority))
            .valid_from(now)
            .valid_until(UnixMillis(90_000))
            .build();
        let issued = node
            .grant(
                &caller,
                GrantCommand::Issue {
                    authorization: ROOT_GRANT,
                    id: HTTP_ACCESS,
                    spec: scope.clone(),
                },
            )
            .await
            .unwrap();
        let (_, credential) = hellas_work::test_support::credentials::issue_one(
            &node,
            &caller,
            ROOT_GRANT,
            scope,
            CredentialHolder::Bearer,
        )
        .await
        .unwrap();
        let access = GatewayAccess::new(node, HTTP_ACCESS, credential)
            .await
            .unwrap();
        Self {
            root,
            access,
            admin,
            clock,
            grant_revision: issued.revision(),
        }
    }
}
fn router(access: GatewayAccess) -> Router {
    Router::new()
        .route(
            "/invoke",
            get(|headers: HeaderMap| async move {
                assert!(!headers.contains_key(header::AUTHORIZATION));
                "reached"
            }),
        )
        .layer(BearerLayer::new(access))
}
async fn status(router: &Router, token: Option<&str>) -> StatusCode {
    let mut request = Request::builder().uri("/invoke");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, token);
    }
    router
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}
#[tokio::test]
async fn bearer_schemes_are_case_insensitive() {
    let fixture = Fixture::new().await;
    let app = router(fixture.access.clone());
    for scheme in ["Bearer", "bearer", "BEARER"] {
        assert_eq!(
            status(&app, Some(&format!("{scheme} {}", fixture.access.bearer()))).await,
            StatusCode::OK
        );
    }
}
#[tokio::test]
async fn malformed_bearers_are_unauthorized() {
    let fixture = Fixture::new().await;
    let app = router(fixture.access.clone());
    assert_eq!(status(&app, None).await, StatusCode::UNAUTHORIZED);
    for value in [
        String::new(),
        "ff".repeat(48),
        format!("{}0", fixture.access.bearer()),
        "z".repeat(96),
    ] {
        assert_eq!(
            status(&app, Some(&format!("Bearer {value}"))).await,
            StatusCode::UNAUTHORIZED
        );
    }
}
#[tokio::test]
async fn legacy_sixty_four_character_tokens_are_unauthorized() {
    let fixture = Fixture::new().await;
    assert_eq!(
        status(
            &router(fixture.access),
            Some(&format!("Bearer {}", "11".repeat(32)))
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn query_tokens_do_not_authenticate() {
    let fixture = Fixture::new().await;
    let request = Request::builder()
        .uri(format!("/invoke?access_token={}", fixture.access.bearer()))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router(fixture.access)
            .oneshot(request)
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn alternate_headers_do_not_authenticate() {
    let fixture = Fixture::new().await;
    let app = router(fixture.access.clone());
    for name in ["x-api-key", "cookie", "proxy-authorization"] {
        let request = Request::builder()
            .uri("/invoke")
            .header(name, format!("Bearer {}", fixture.access.bearer()))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
#[tokio::test]
async fn repeated_authorization_headers_are_unauthorized() {
    let fixture = Fixture::new().await;
    let token = format!("Bearer {}", fixture.access.bearer());
    let request = Request::builder()
        .uri("/invoke")
        .header(header::AUTHORIZATION, &token)
        .header(header::AUTHORIZATION, &token)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router(fixture.access)
            .oneshot(request)
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn gateway_access_debug_redacts_credentials() {
    let fixture = Fixture::new().await;
    assert_eq!(format!("{:?}", fixture.access), "GatewayAccess(redacted)");
}
#[tokio::test]
async fn http_admission_consults_current_authority() {
    enum Change {
        Credential,
        Grant,
        Expiry,
    }
    for revoke in [Change::Credential, Change::Grant, Change::Expiry] {
        let fixture = Fixture::new().await;
        let node = &fixture.access.node;
        let caller = hellas_work::test_support::session(node, &fixture.admin).await;
        let app = router(fixture.access.clone());
        let token = format!("Bearer {}", fixture.access.bearer());
        assert_eq!(status(&app, Some(&token)).await, StatusCode::OK);
        match revoke {
            Change::Credential => {
                node.revoke_credential(
                    &caller,
                    ROOT_GRANT,
                    fixture.access.credential.id(),
                    Revision(1),
                )
                .await
                .unwrap();
            }
            Change::Grant => {
                node.grant(
                    &caller,
                    GrantCommand::Revoke {
                        authorization: ROOT_GRANT,
                        id: HTTP_ACCESS,
                        expected: fixture.grant_revision,
                    },
                )
                .await
                .unwrap();
            }
            Change::Expiry => {
                fixture.clock.set(UnixMillis(90_000));
            }
        }
        assert_eq!(status(&app, Some(&token)).await, StatusCode::UNAUTHORIZED);
    }
}
#[tokio::test]
async fn listening_remotely_requires_explicit_opt_in() {
    bind_addr("127.0.0.1", 0, false).await.unwrap();
    assert_err!(
        bind_addr("0.0.0.0", 0, false).await,
        crate::GatewayError::Config(crate::GatewayConfigError::RemoteBinding)
    );
    bind_addr("0.0.0.0", 0, true).await.unwrap();
}

#[tokio::test]
async fn administrator_credentials_cannot_be_exposed_as_http_bearers() {
    let fixture = Fixture::new().await;
    let node = &fixture.access.node;
    let caller = hellas_work::test_support::session(node, &fixture.admin).await;
    assert_err!(
        node.authorize_gateway(&caller, ROOT_GRANT).await,
        hellas_work::work_store::grant::NodeStoreError::Authority(AuthorityError::Denied)
    );
}

#[tokio::test]
async fn each_principal_is_admitted_under_its_own_grant() {
    use hellas_work::test_support::actors::{FRIEND, STRANGER};
    let fixture = Fixture::new().await;
    let node = &fixture.access.node;
    let caller = hellas_work::test_support::session(node, &fixture.admin).await;
    let authority = caller.authority();
    let scope = |actor| {
        Rights::new(authority, actor)
            .allow(GATEWAY_INVOKE, host_resource(authority))
            .valid_from(UnixMillis(1000))
            .valid_until(UnixMillis(90_000))
            .build()
    };
    let bearer = async |actor| {
        let (_, credential) = hellas_work::test_support::credentials::issue_one(
            node,
            &caller,
            ROOT_GRANT,
            scope(actor),
            CredentialHolder::Bearer,
        )
        .await
        .unwrap();
        format!(
            "Bearer {}{}",
            credential.id(),
            hellas_rpc::provenance::encode_hex(credential.expose_secret())
        )
    };
    let friend_grant = GrantId([105; 16]);
    let issued = node
        .grant(
            &caller,
            GrantCommand::Issue {
                authorization: ROOT_GRANT,
                id: friend_grant,
                spec: scope(FRIEND),
            },
        )
        .await
        .unwrap();
    let app = router(fixture.access.clone());
    let friend = bearer(FRIEND).await;
    // A bearer whose subject holds no gateway.invoke grant is refused.
    let stranger = bearer(STRANGER).await;
    assert_eq!(status(&app, Some(&friend)).await, StatusCode::OK);
    assert_eq!(
        status(&app, Some(&stranger)).await,
        StatusCode::UNAUTHORIZED
    );
    // A device-held credential never authenticates by its secret.
    let (_, held) = hellas_work::test_support::credentials::issue_one(
        node,
        &caller,
        ROOT_GRANT,
        scope(FRIEND),
        FRIEND.holder(),
    )
    .await
    .unwrap();
    let held = format!(
        "Bearer {}{}",
        held.id(),
        hellas_rpc::provenance::encode_hex(held.expose_secret())
    );
    assert_eq!(status(&app, Some(&held)).await, StatusCode::UNAUTHORIZED);
    node.grant(
        &caller,
        GrantCommand::Revoke {
            authorization: ROOT_GRANT,
            id: friend_grant,
            expected: issued.revision(),
        },
    )
    .await
    .unwrap();
    assert_eq!(status(&app, Some(&friend)).await, StatusCode::UNAUTHORIZED);
    // The gateway's own bearer is unaffected.
    let own = format!("Bearer {}", fixture.access.bearer());
    assert_eq!(status(&app, Some(&own)).await, StatusCode::OK);
}
