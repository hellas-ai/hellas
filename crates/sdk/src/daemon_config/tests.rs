use super::*;

fn backend(kind: BackendKind) -> Backend {
    Backend {
        max_in_flight: NonZeroUsize::MIN,
        kind,
    }
}
fn local(runtime: &str) -> Backend {
    backend(BackendKind::Local {
        runtime: runtime.into(),
        content: vec![],
    })
}
fn info(id: &str, evaluator: &str) -> hellas_gateway::BackendInfo {
    hellas_gateway::BackendInfo {
        id: id.into(),
        evaluator: Some(evaluator.into()),
        max_in_flight: 1,
        in_flight: 0,
        down: false,
    }
}

#[test]
fn empty_daemon_is_valid_but_impossible_capacity_is_not() {
    let mut document = Document::default();
    document.validate().unwrap();
    let mut gpu = local("auto");
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
            port: 0,
            backends: vec!["remote".into()],
        },
    );
    for kind in [
        BackendKind::Grant {
            access: "offer.json".into(),
            resource: None,
            evaluator: None,
            trust: None,
        },
        BackendKind::Paid {
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
            ("first".into(), local("auto")),
            ("second".into(), local("cuda")),
        ]
        .into(),
        ..Default::default()
    };
    document.listeners.insert(
        "work".into(),
        Listener::Iroh {
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
            port: 0,
            backends: vec!["first".into(), "second".into()],
        },
    );
    assert_eq!(
        document.validate_resolved(&[]),
        Err("ambiguous iroh invocation key")
    );
}
