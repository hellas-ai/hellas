use super::super::config;
use super::*;
use axum::http::HeaderValue;
use hellas_rpc::Assurance;
use serde_json::json;

fn config() -> HttpGatewayConfig {
    let backend = |credential: &str, models: &[&str]| {
        json!({
            "credential":credential, "models":models,
            "routes":[{"path":"/v1/chat/completions","method":"POST","url":"https://example.com/v1/chat/completions"},
                      {"path":"/v1/responses","method":"POST","url":"https://example.com/v1/responses"}]
        })
    };
    serde_json::from_value(json!({"service":"http","method":"request","max_in_flight":1,
        "backends":{"a":backend("a", &["k3"]),"b":backend("b", &["k3"]),"c":backend("c", &["other"])}})).unwrap()
}

fn routing(config: HttpGatewayConfig) -> Arc<Routing> {
    config.validate().unwrap();
    let trust = hellas_client::ProviderTrustAnchor {
        expected_genesis: ContentId::hash(b"provider"),
        required_assurance: Assurance::ProducerSigned,
        apple_app_attest: None,
    };
    Arc::new(
        Routing::new(
            &config,
            ExecutionRoute::remote(None, vec![], 0, trust.clone()),
            trust,
        )
        .unwrap(),
    )
}

fn select(routing: &Routing, model: &str, session: &str) -> Result<Selected, Unavailable> {
    routing.select(
        "/v1/chat/completions",
        "POST",
        &HeaderMap::new(),
        &serde_json::to_vec(&json!({"model":model,"prompt_cache_key":session})).unwrap(),
        None,
    )
}

#[test]
fn models_admission_and_cooldowns_do_not_move_existing_sessions() {
    let routing = routing(config());
    let first = select(&routing, "k3", "first").unwrap();
    assert_eq!(first.backend, 0);
    assert_eq!(
        select(&routing, "k3", "first").err().unwrap().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let second = select(&routing, "k3", "second").unwrap();
    assert_eq!(second.backend, 1);
    assert_eq!(
        select(&routing, "k3", "third").err().unwrap().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(select(&routing, "other", "first").unwrap().backend, 2);
    assert_eq!(
        select(&routing, "unconfigured", "first")
            .err()
            .unwrap()
            .status,
        StatusCode::NOT_FOUND
    );
    drop((first, second));
    let rate_limit = HeaderMap::from_iter([(
        "retry-after".parse().unwrap(),
        HeaderValue::from_static("60"),
    )]);
    routing.observe(0, 429, &rate_limit);
    for binding in routing.state.lock().unwrap().bindings.values_mut() {
        binding.touched = Instant::now() - SESSION_IDLE / 2;
    }
    let pinned = select(&routing, "k3", "first").err().unwrap();
    assert!(
        routing
            .state
            .lock()
            .unwrap()
            .bindings
            .values()
            .any(|b| b.backend == Some(0) && b.touched.elapsed() < Duration::from_secs(1)),
        "rate-limited retries still keep a session active"
    );
    assert_eq!(pinned.status, StatusCode::TOO_MANY_REQUESTS);
    assert!((59..=61).contains(&pinned.retry.unwrap()));
    assert_eq!(select(&routing, "k3", "third").unwrap().backend, 1);
    *routing.backends[0].account.backoff.lock().unwrap() = None;
    assert_eq!(select(&routing, "k3", "first").unwrap().backend, 0);
}

#[test]
fn connection_is_a_fallback_and_explicit_sessions_survive_reconnects() {
    let routing = routing(config());
    let body = br#"{"model":"k3"}"#;
    let connections: Vec<_> = (0..4)
        .map(|id| crate::ConnectionId {
            id,
            alive: Arc::new(()),
        })
        .collect();
    let request = |connection: usize, headers: &HeaderMap| {
        routing
            .select(
                "/v1/chat/completions",
                "POST",
                headers,
                body,
                Some(&connections[connection]),
            )
            .unwrap()
    };
    let empty = HeaderMap::new();
    assert_eq!(request(1, &empty).backend, 0);
    assert_eq!(request(1, &empty).backend, 0);
    assert_eq!(request(2, &empty).backend, 1);
    let headers = HeaderMap::from_iter([(
        "session-id".parse().unwrap(),
        HeaderValue::from_static("new-session"),
    )]);
    assert_eq!(request(2, &headers).backend, 0);
    assert_eq!(request(3, &headers).backend, 0);
}

#[test]
fn concurrent_first_requests_bind_atomically_and_release_capacity() {
    let mut config = config();
    config.max_in_flight = 32;
    let routing = routing(config);
    let threads: Vec<_> = (0..16)
        .map(|_| {
            let routing = routing.clone();
            std::thread::spawn(move || select(&routing, "k3", "same-session").unwrap())
        })
        .collect();
    let requests: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert!(requests.iter().all(|r| r.backend == requests[0].backend));
    let backend = requests[0].backend;
    assert_eq!(
        routing.backends[backend].account.slots.available_permits(),
        16
    );
    drop(requests);
    assert_eq!(
        routing.backends[backend].account.slots.available_permits(),
        32
    );
}

#[test]
fn server_state_uses_its_original_backend_and_unknown_or_conflicting_state_fails_closed() {
    let routing = routing(config());
    let request = |value| {
        routing.select(
            "/v1/responses",
            "POST",
            &HeaderMap::new(),
            &serde_json::to_vec(&value).unwrap(),
            None,
        )
    };
    let first = request(json!({"model":"k3","prompt_cache_key":"first"})).unwrap();
    let binding = routing
        .response_binding(first.backend, "/v1/responses")
        .unwrap();
    binding.observe(
        &json!({"response":{"object":"response","id":"resp_a","conversation":{"id":"conv_a"}}}),
    );
    drop(first);
    assert_eq!(
        request(json!({"previous_response_id":"resp_a"}))
            .unwrap()
            .backend,
        0
    );
    assert_eq!(
        request(json!({"model":"k3","previous_response_id":"resp_a"}))
            .unwrap()
            .backend,
        0
    );
    assert_eq!(
        request(json!({"model":"k3","conversation":"conv_a"}))
            .unwrap()
            .backend,
        0
    );
    assert_eq!(
        request(json!({"model":"k3","previous_response_id":"unknown"}))
            .err()
            .unwrap()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(json!({"model":"k3","prompt_cache_key":"second"}))
            .unwrap()
            .backend,
        1
    );
    assert_eq!(
        request(json!({"model":"k3","prompt_cache_key":"second","previous_response_id":"resp_a"}))
            .err()
            .unwrap()
            .status,
        StatusCode::CONFLICT
    );
    // Neither account may repair a collision by reporting the ID again.
    for backend in [1, 0, 1] {
        routing
            .response_binding(backend, "/v1/responses")
            .unwrap()
            .observe(&json!({"object":"response","id":"resp_a"}));
        assert_eq!(
            request(json!({"model":"k3","previous_response_id":"resp_a"}))
                .err()
                .unwrap()
                .status,
            StatusCode::CONFLICT
        );
    }
}

#[test]
fn full_affinity_table_does_not_evict_live_sessions_and_expired_server_state_is_rejected() {
    let routing = routing(config());
    assert_eq!(select(&routing, "k3", "keep").unwrap().backend, 0);
    {
        let mut state = routing.state.lock().unwrap();
        for i in 1..MAX_BINDINGS {
            state.bindings.insert(
                ContentId::hash(&i.to_le_bytes()),
                Binding {
                    backend: Some(1),
                    touched: Instant::now(),
                    connection: None,
                },
            );
        }
    }
    assert_eq!(select(&routing, "k3", "keep").unwrap().backend, 0);
    assert_eq!(
        select(&routing, "k3", "new").err().unwrap().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    {
        let mut state = routing.state.lock().unwrap();
        for binding in state.bindings.values_mut() {
            binding.touched = Instant::now() - SESSION_IDLE - Duration::from_secs(1);
        }
    }
    assert!(select(&routing, "k3", "new").is_ok());
    routing
        .response_binding(0, "/v1/responses")
        .unwrap()
        .observe(&json!({"object":"response","id":"expired"}));
    let key = routing.key("response", &["/v1/responses", "expired"]);
    routing
        .state
        .lock()
        .unwrap()
        .bindings
        .get_mut(&key)
        .unwrap()
        .touched = Instant::now() - SESSION_IDLE - Duration::from_secs(1);
    assert_eq!(
        routing
            .select(
                "/v1/responses",
                "POST",
                &HeaderMap::new(),
                br#"{"model":"k3","previous_response_id":"expired"}"#,
                None
            )
            .err()
            .unwrap()
            .status,
        StatusCode::CONFLICT
    );
}

#[test]
fn repeated_aliases_share_limits_but_distinct_provider_nodes_keep_them_separate() {
    let mut config = config();
    config.backends.get_mut("b").unwrap().credential = Some("a".into());
    let shared = routing(config.clone());
    let _request = select(&shared, "k3", "first").unwrap();
    assert_eq!(
        select(&shared, "k3", "second").err().unwrap().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let node = iroh::SecretKey::generate().public();
    config.backends.get_mut("b").unwrap().provider = Some(config::Provider {
        node_id: node,
        node_addrs: vec![],
        genesis: ContentId::hash(b"other"),
    });
    let mut same_provider = config.clone();
    same_provider
        .backends
        .get_mut("b")
        .unwrap()
        .provider
        .as_mut()
        .unwrap()
        .genesis = ContentId::hash(b"provider");
    let same_provider = routing(same_provider);
    let _first = select(&same_provider, "k3", "first").unwrap();
    assert_eq!(
        select(&same_provider, "k3", "second").err().unwrap().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let split = routing(config);
    let _first = select(&split, "k3", "first").unwrap();
    assert_eq!(select(&split, "k3", "second").unwrap().backend, 1);
    assert!(
        matches!(&split.backends[1].remote, ExecutionRoute::RemoteDirect(target) if target.addr.id==node && target.provider_trust.expected_genesis==ContentId::hash(b"other"))
    );
}

#[test]
fn closed_client_connections_release_their_affinity_entries() {
    let routing = routing(config());
    for id in 0..32 {
        let connection = crate::ConnectionId {
            id,
            alive: Arc::new(()),
        };
        routing
            .select(
                "/v1/chat/completions",
                "POST",
                &HeaderMap::new(),
                br#"{"model":"k3"}"#,
                Some(&connection),
            )
            .unwrap();
        assert_eq!(routing.state.lock().unwrap().bindings.len(), 1);
    }
    select(&routing, "k3", "explicit-session").unwrap();
    assert_eq!(routing.state.lock().unwrap().bindings.len(), 1);
}

#[test]
fn account_backoff_is_shared_and_never_shortened_by_another_response() {
    let account = Arc::new(Account::new(1));
    let other_route = account.clone();
    let header = |seconds: &'static str| {
        HeaderMap::from_iter([(
            "retry-after".parse().unwrap(),
            HeaderValue::from_static(seconds),
        )])
    };
    assert!(account.cooldown().is_none());
    account.observe(429, &header("60"));
    assert!(other_route.cooldown().unwrap().1 > Duration::from_secs(59));
    other_route.observe(429, &header("1"));
    assert!(account.cooldown().unwrap().1 > Duration::from_secs(59));
    other_route.observe(503, &header("120"));
    assert_eq!(account.cooldown().unwrap().0, 503);
    assert!(account.cooldown().unwrap().1 > Duration::from_secs(119));
    // A short rate limit must not turn a retriable overload into a quota error.
    other_route.observe(429, &header("1"));
    assert_eq!(account.cooldown().unwrap().0, 503);
    account.observe(200, &header("600"));
    assert!(account.cooldown().unwrap().1 < Duration::from_secs(121));
    *account.backoff.lock().unwrap() = Some((Instant::now(), 503));
    assert!(account.cooldown().is_none());
    let permit = account.slots.clone().try_acquire_owned().unwrap();
    assert!(other_route.slots.clone().try_acquire_owned().is_err());
    drop(permit);
    assert!(other_route.slots.clone().try_acquire_owned().is_ok());
}

#[test]
fn new_sessions_use_relative_account_load() {
    let mut config = config();
    config.backends.get_mut("b").unwrap().max_in_flight = Some(2);
    let routing = routing(config);
    let a = select(&routing, "k3", "a").unwrap();
    let b = select(&routing, "k3", "b").unwrap();
    let c = select(&routing, "k3", "c").unwrap();
    assert_eq!((a.backend, b.backend, c.backend), (0, 1, 1));
    drop(a);
    assert_eq!(select(&routing, "k3", "d").unwrap().backend, 0);
}
