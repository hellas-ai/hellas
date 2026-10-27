use super::*;
use hellas_channel::model::{fetch::PreparedPaidFetchInputV1, profile::PreparedWorkInput};
use hellas_rpc::http_fetch::{HttpFetchRequest, HttpTrustRoots};
use {crate::test_support::ids, hellas_channel::test_support::actors::*};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Stranger,
    WrongApplication,
    WrongAuthorization,
    WrongProducer,
    StaleRevision,
    StaleGeneration,
    OutOfScope,
    Origin,
    Path,
    TlsRoots,
    Credential,
    Paused,
}
struct RefusalWorld {
    world: TestService,
    work: crate::grant_service::GrantWork,
    backend: Backend,
    request: AcceptWorkRequest,
    revision: Revision,
}
impl Case {
    async fn arrange(self, path: &std::path::Path) -> RefusalWorld {
        let resource = chat_resource("https://glm.test", 8);
        let mut allowance = Allowance::responses(ids::ALLOWANCE, FRIEND);
        use_https(&mut allowance.definition.policies[0], resource.clone());
        allowance.definition.enabled = self != Self::Paused;
        let mut node = Node::bootstrap(path)
            .with_allowance(allowance)
            .with_grant(
                ids::FRIEND_GRANT,
                Rights::new(authority(), FRIEND)
                    .allow(
                        crate::grant_service::WORK_EXECUTE,
                        crate::grant_service::allowance_resource(authority(), ids::ALLOWANCE),
                    )
                    .valid_until(UnixMillis(100_000))
                    .build(),
            )
            .build()
            .await;
        let mut request = node.proposal(FRIEND, ids::ALLOWANCE, 1);
        if self == Self::StaleRevision {
            let mut definition = node.store.state().grant(ids::ALLOWANCE).unwrap().clone();
            definition.revision.0 += 1;
            definition.policies[0].revision.0 += 1;
            node.store
                .configure_resource(definition.policies[0].clone(), node.clock.now())
                .await
                .unwrap();
            node.store
                .define(definition, node.clock.now())
                .await
                .unwrap();
        } else if self == Self::StaleGeneration {
            node.store
                .bump_generation(ids::ALLOWANCE, node.clock.now())
                .await
                .unwrap();
        }
        let signer = if self == Self::WrongProducer {
            STRANGER
        } else {
            FRIEND
        };
        match self {
            Self::Stranger => {
                request.authorization.channel_id = ChannelId(Digest::hash(b"unknown channel"))
            }
            Self::OutOfScope => {
                request.authorization.work_policy_digest = Digest::hash(b"ungranted policy")
            }
            Self::Origin | Self::Path | Self::TlsRoots | Self::Credential => {
                let mut http = HttpFetchRequest {
                    url: "https://glm.test/v1/chat/completions".into(),
                    method: "POST".into(),
                    headers: vec![],
                    body_base64: "eyJtYXhfdG9rZW5zIjo4fQ==".into(),
                    tls: resource.tls,
                    credential: None,
                    max_response_bytes: 4096,
                };
                match self {
                    Self::Origin => http.url = "https://other.test/v1/chat/completions".into(),
                    Self::Path => http.url = "https://glm.test/v1/other".into(),
                    Self::TlsRoots => {
                        http.tls.roots = HttpTrustRoots::Certificates {
                            der_base64: vec!["AQ==".into()],
                        }
                    }
                    Self::Credential => http.credential = Some("other-account".into()),
                    _ => unreachable!(),
                }
                let contract = hellas_rpc::FetchContract::http().unwrap();
                let events = hellas_rpc::fetch::build_input_events_with_retention(
                    "openai",
                    "responses",
                    &serde_json::to_vec(&http).unwrap(),
                    contract.manifest_id(),
                    Assurance::ProducerSigned,
                    &signer.node_key(),
                    Retention::Ephemeral,
                )
                .unwrap();
                request.input = PreparedWorkInput::from(
                    PreparedPaidFetchInputV1::new(&events, &contract).unwrap(),
                );
                request.authorization.input_content =
                    hellas_rpc::ContentRef::for_bytes(&request.input.encode().unwrap());
                request.authorization.prepared_input_digest = request
                    .input
                    .bound_digest(network(), request.authorization.channel_id.0)
                    .unwrap();
                request.authorization.request_commitment = RequestCommitment::from_digest(
                    request.input.input_commitment().unwrap().digest(),
                );
            }
            _ => {}
        }
        request.signature = signer.node_key().sign_digest(request.work()).unwrap();
        let revision = node.store.state().grant(ids::ALLOWANCE).unwrap().revision;
        let backend = Backend {
            signer: Arc::new(PROVIDER.node_key()),
            ..Backend::default()
        };
        let world = node.serve(backend.clone());
        let work = match self {
            Self::WrongApplication => world.work(ROOT, ids::FRIEND_GRANT).await,
            Self::WrongAuthorization => world.work(FRIEND, ids::ROOT_GRANT).await,
            _ => world.work(FRIEND, ids::FRIEND_GRANT).await,
        };
        RefusalWorld {
            world,
            work,
            backend,
            request: request.request(),
            revision,
        }
    }
}

#[tokio::test]
async fn grant_refusals_preserve_the_typed_reason() {
    use GrantRefusalCode as C;
    for (case, expected) in [
        (Case::Stranger, C::Unauthorized),
        (Case::WrongApplication, C::Unauthorized),
        (Case::WrongAuthorization, C::Unauthorized),
        (Case::WrongProducer, C::Unauthorized),
        (Case::StaleRevision, C::StaleRevision),
        (Case::StaleGeneration, C::StaleGeneration),
        (Case::OutOfScope, C::OutOfScope),
        (Case::Origin, C::Origin),
        (Case::Path, C::PathMethod),
        (Case::TlsRoots, C::Tls),
        (Case::Credential, C::Credential),
        (Case::Paused, C::Paused),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let fixture = case.arrange(directory.path()).await;

        let response =
            crate::test_support::accept_grant(&fixture.work, &fixture.request, &FRIEND.node_key())
                .await;

        if case == Case::StaleRevision {
            let Some(accept_work_response::Outcome::Refused(ref detail)) = response.outcome else {
                panic!("{case:?}: {response:?}")
            };
            assert_eq!(
                detail.grant.as_ref().unwrap().current_revision,
                fixture.revision.0
            );
        }
        assert_eq!(refusal(response), expected, "{case:?}");
        assert_eq!(fixture.backend.calls.load(Ordering::SeqCst), 0, "{case:?}");
        assert_eq!(fixture.backend.slots.available_permits(), 1, "{case:?}");
        within(fixture.world.service.drain()).await.unwrap();
    }
}
