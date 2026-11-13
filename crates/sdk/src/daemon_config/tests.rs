use super::*;

fn backend(kind: BackendKind) -> Backend {
    Backend {
        max_in_flight: NonZeroUsize::MIN,
        kind,
    }
}
fn local(evaluator: &str) -> Backend {
    backend(BackendKind::Local {
        evaluator: Some(evaluator.into()),
        content: vec![],
    })
}
fn info(id: &str, evaluator: &str) -> hellas_gateway::BackendInfo {
    hellas_gateway::BackendInfo {
        instance: 1,
        id: id.into(),
        evaluator: Some(evaluator.into()),
        max_in_flight: 1,
        in_flight: 0,
        down: false,
        error: None,
    }
}

#[test]
fn empty_daemon_is_valid_but_impossible_capacity_is_not() {
    let mut document = Document::default();
    document.validate().unwrap();
    let mut gpu = local("opaque/first");
    gpu.max_in_flight = NonZeroUsize::new(tokio::sync::Semaphore::MAX_PERMITS + 1).unwrap();
    document.backends.insert("gpu".into(), gpu);
    assert_eq!(
        document.validate(),
        Err("backend capacity exceeds the runtime limit")
    );
}

#[test]
fn iroh_only_accepts_local_and_fetch_backends() {
    let mut document = Document::default();
    document.listeners.insert(
        "work".into(),
        Listener::Iroh {
            chain: None,
            port: 0,
            backends: vec!["remote".into()],
        },
    );
    for kind in [
        BackendKind::Grant {
            access: None,
            resource: None,
            evaluator: None,
            trust: None,
        },
        BackendKind::Paid {
            addresses: vec![],
            acceptance_blocks: 300,
            terminal_blocks: 3000,
            payment_blocks: 600,
            timeout_seconds: None,
            chain: None,
            provider: "provider".into(),
            max_price: 1,
            evaluator: None,
            trust: None,
        },
    ] {
        document.backends.insert("remote".into(), backend(kind));
        assert_eq!(
            document.validate(),
            Err("iroh listeners only serve local and fetch backends")
        );
    }
}

#[test]
fn iroh_duplicate_keys_use_resolved_evaluator_ids() {
    let mut document = Document {
        backends: [
            ("first".into(), local("opaque/first")),
            ("second".into(), local("opaque/second")),
        ]
        .into(),
        ..Default::default()
    };
    document.listeners.insert(
        "work".into(),
        Listener::Iroh {
            chain: None,
            port: 0,
            backends: vec!["first".into(), "second".into()],
        },
    );
    assert_eq!(
        document.validate_resolved(&[
            info("first", "opaque/evaluator"),
            info("second", "opaque/evaluator")
        ]),
        Err("ambiguous iroh invocation key")
    );
    document
        .validate_resolved(&[info("first", "opaque/one"), info("second", "opaque/two")])
        .unwrap();
    assert_eq!(
        document.validate_resolved(&[]),
        Err("local backend has no registered evaluator")
    );
}

#[test]
fn direct_http_fetch_is_allowed_and_iroh_fetch_keys_must_be_unique() {
    let mut document = Document::default();
    let fetch = backend(BackendKind::Fetch {
        service: "openai".into(),
        method: "responses".into(),
        upstream: Upstream::OpenaiResponses {
            secret: Some("write-only".into()),
        },
    });
    document.backends = [("first".into(), fetch.clone()), ("second".into(), fetch)].into();
    document.routes.push(hellas_gateway::Route {
        backends: vec!["first".into()],
        presentation: hellas_gateway::Presentation::Responses {
            service: "openai".into(),
            method: "responses".into(),
            models: vec![],
            overrides: Default::default(),
        },
    });
    document.validate().unwrap();
    document.listeners.insert(
        "work".into(),
        Listener::Iroh {
            chain: None,
            port: 0,
            backends: vec!["first".into(), "second".into()],
        },
    );
    assert_eq!(
        document.validate_resolved(&[]),
        Err("ambiguous iroh invocation key")
    );
}

#[test]
fn keys_are_inputs_and_only_omitted_keys_in_existing_entries_are_retained() {
    let mut document: Document = serde_json::from_value(serde_json::json!({
        "listeners": {}, "backends": {
            "http": { "kind": "fetch", "service": "https", "method": "request", "max_in_flight": 2,
                "upstream": { "kind": "http", "allowed_hosts": ["example.org"], "credentials": {
                    "main": { "allowed_origins": ["https://example.org"], "allowed_paths": ["/api"], "allowed_methods": ["POST"], "header_name": "authorization", "secret": "Bearer first-key" }
                }}
            },
            "responses": { "kind": "fetch", "service": "openai", "method": "responses", "max_in_flight": 1,
                "upstream": { "kind": "openai_responses", "secret": "second-key" }
            }
        }
    })).unwrap();
    document.backends.insert(
        "grant".into(),
        Backend {
            max_in_flight: std::num::NonZeroUsize::MIN,
            kind: BackendKind::Grant {
                access: Some("private-grant-credential".into()),
                resource: None,
                evaluator: None,
                trust: None,
            },
        },
    );
    let input = serde_json::to_string(&document).unwrap();
    assert!(input.contains("first-key") && input.contains("second-key"));
    let (mut redacted, secrets) = document.redacted();
    let echo = serde_json::to_string(&redacted).unwrap();
    assert!(
        !echo.contains("first-key")
            && !echo.contains("second-key")
            && !echo.contains("private-grant-credential")
    );
    redacted.restore_secrets(&secrets);
    assert_eq!(serde_json::to_string(&redacted).unwrap(), input);

    let (mut changed, _) = document.redacted();
    changed.backends.remove("http");
    changed.backends.remove("grant");
    let BackendKind::Fetch {
        upstream: Upstream::OpenaiResponses { secret },
        ..
    } = &mut changed.backends.get_mut("responses").unwrap().kind
    else {
        unreachable!()
    };
    *secret = Some("rotated-key".into());
    changed.restore_secrets(&secrets);
    let (_, retained) = changed.redacted();
    assert_eq!(retained.0.len(), 1);
    assert_eq!(retained.0["responses"]["bearer"], "rotated-key");
}

#[test]
fn flattened_backend_and_route_reject_unknown_fields() {
    let backend = serde_json::json!({"kind":"local", "max_in_flight":1, "typo":true});
    assert!(serde_json::from_value::<Backend>(backend).is_err());
    let route = serde_json::json!({"kind":"responses", "backends":["a"], "service":"openai", "method":"responses", "typo":true});
    assert!(serde_json::from_value::<hellas_gateway::Route>(route).is_err());
}

#[tokio::test]
async fn model_and_operator_inputs_keep_their_terms_in_one_configuration() {
    use hellas_authority::model::grant::responses::ResponsesResource;
    use hellas_rpc::protocol::invocation::Admission;
    let mut document = Document::default();
    document
        .add_upstream("models", "https://example.com/api", Some("key".into()))
        .unwrap();
    document.add_upstream_model("one", "models").unwrap();
    document.add_upstream_model("two", "models").unwrap();
    document.backends.insert(
        "operator".into(),
        backend(BackendKind::Fetch {
            service: "openai".into(),
            method: "responses".into(),
            upstream: Upstream::OpenaiResponses {
                secret: Some("key".into()),
            },
        }),
    );
    let mut resource = Resource::new(
        "operator".into(),
        "operator".into(),
        ResourceKind::Responses {
            responses: ResponsesResource {
                model: "one".into(),
                max_output_tokens: 64,
                settings: Default::default(),
            },
        },
    );
    resource.max_job_millis = std::num::NonZeroU64::new(123_000).unwrap();
    document.resources.push(resource);
    document
        .backends
        .insert("gpu".into(), local("opaque/second"));
    document.routes.push(hellas_gateway::Route {
        backends: vec!["gpu".into()],
        presentation: hellas_gateway::Presentation::Model {
            model: "tiny".into(),
            modality: hellas_client::model::ModelKind::Text,
            package: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../client/src/model/package/mini-qwen3.gguf"),
            max_tokens: 1,
        },
    });
    document.listeners.insert(
        "work".into(),
        Listener::Iroh {
            port: 0,
            chain: None,
            backends: vec!["models".into(), "operator".into(), "gpu".into()],
        },
    );
    let evaluator = hellas_client::model::evaluator(hellas_client::model::GpuDialect::Cuda);
    let configuration = document
        .configuration_for_test(&[info("gpu", &evaluator)])
        .await
        .unwrap();
    assert_eq!(configuration.machine().unwrap().max_in_flight.get(), 64);
    assert_eq!(configuration.resources().len(), 3);
    let model = configuration.resource("models").unwrap();
    assert_eq!(model.pricing.rates, Some(vec![]));
    let paths = model.https.as_ref().unwrap().model_policy.as_ref().unwrap();
    assert_eq!(paths.len(), 3);
    assert!(paths.iter().all(|path| path.models == ["one", "two"]));
    assert_eq!(
        model.invocation_policy.limits.execution_timeout_ms,
        86_400_000
    );
    let operator = configuration.resource("operator").unwrap();
    assert_eq!(operator.pricing.rates, None);
    assert_eq!(
        operator.invocation_policy.limits.execution_timeout_ms,
        123_000
    );
    assert_eq!(operator.invocation_policy.limits.max_output_bytes, 1 << 20);
    let compute = configuration.resource("tiny").unwrap();
    assert_eq!(compute.pricing.rates, Some(vec![]));
    assert_eq!(
        compute.invocation_policy.limits.execution_timeout_ms,
        900_000
    );
    assert!(
        matches!(&compute.invocation_policy.admissions[..], [Admission::Compute { evaluator: actual, .. }] if actual == &evaluator)
    );
    let mut explicit = Resource::new(
        "models".into(),
        "models".into(),
        ResourceKind::Https {
            https: model.https.clone().unwrap(),
        },
    );
    explicit.max_job_millis = std::num::NonZeroU64::new(123_000).unwrap();
    document.resources.push(explicit);
    let configured = document
        .configuration_for_test(&[info("gpu", &evaluator)])
        .await
        .unwrap();
    let explicit = configured.resource("models").unwrap();
    assert_eq!(explicit.invocation_policy.limits.max_output_bytes, 4 << 20);
    assert_eq!(
        explicit.invocation_policy.limits.execution_timeout_ms,
        123_000
    );
}

#[test]
fn changed_upstream_does_not_inherit_a_stored_key() {
    let mut original = Document::default();
    original
        .add_upstream(
            "api",
            "https://api.good.example/v1",
            Some("stored-key".into()),
        )
        .unwrap();
    let mut edited = original.redacted().0;
    edited.remove_backend("api").unwrap();
    edited
        .add_upstream("api", "https://collector.evil.example/v1", None)
        .unwrap();
    edited.retain_secrets(&original);
    let BackendKind::Fetch {
        upstream:
            Upstream::Http {
                allowed_hosts,
                credentials,
                ..
            },
        ..
    } = &edited.backends["api"].kind
    else {
        unreachable!()
    };
    assert_eq!(allowed_hosts, &["collector.evil.example".to_string()]);
    assert_eq!(credentials["api"].secret, None);
}

#[tokio::test]
async fn granted_upstream_routes_preserve_the_direct_local_paths() {
    let mut document = Document::default();
    document
        .add_upstream(
            "api",
            "https://example.com/prefix/v1",
            Some("secret".into()),
        )
        .unwrap();
    document.add_upstream_model("model", "api").unwrap();
    document.listeners.insert(
        "work".into(),
        Listener::Iroh {
            port: 0,
            chain: None,
            backends: vec!["api".into()],
        },
    );
    let configuration = document.configuration_for_test(&[]).await.unwrap();
    let granted =
        crate::gateway_work::grant_routes(configuration.resource("api").unwrap(), "api").unwrap();
    assert_eq!(
        serde_json::to_value(granted).unwrap(),
        serde_json::to_value(&document.routes).unwrap()
    );
}
