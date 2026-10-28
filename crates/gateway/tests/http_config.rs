use hellas_gateway::{GatewayConfigError, GatewayError, HttpGatewayConfig};
use serde_json::json;

fn config() -> HttpGatewayConfig {
    serde_json::from_value(json!({
        "service": "http", "method": "fetch",
        "routes": [{"path": "/v1/responses", "method": "POST", "url": "https://api.example.com/v1/responses"}],
    })).unwrap()
}

#[test]
fn public_http_validation_accepts_valid_routes_and_refuses_invalid_configurations() {
    let c = config();
    c.validate().unwrap();
    let mut c = config();
    let mut get = c.routes[0].clone();
    get.method = "GET".into();
    c.routes.push(get);
    c.validate().unwrap();

    let mut c = config();
    c.routes.clear();
    assert!(matches!(
        c.validate(),
        Err(GatewayError::Config(GatewayConfigError::RouteMode))
    ));
    for concurrency in [0, 1025] {
        let mut c = config();
        c.max_in_flight = concurrency;
        assert!(matches!(
            c.validate(),
            Err(GatewayError::Config(GatewayConfigError::HttpConcurrency))
        ));
    }
    let mut c = config();
    c.routes.push(c.routes[0].clone());
    assert!(matches!(
        c.validate(),
        Err(GatewayError::Config(GatewayConfigError::DuplicateRoute))
    ));
    for path in ["relative", "/path?query", "/path#fragment", "/{param}"] {
        let mut c = config();
        c.routes[0].path = path.into();
        assert!(matches!(
            c.validate(),
            Err(GatewayError::Config(GatewayConfigError::RoutePath))
        ));
    }
    let mut c = config();
    c.routes[0]
        .headers
        .push(("authorization".into(), "inline-secret".into()));
    assert!(matches!(
        c.validate(),
        Err(GatewayError::Config(GatewayConfigError::CredentialAlias))
    ));
    for url in ["http://api.example.com", "not a URL"] {
        let mut c = config();
        c.routes[0].url = url.into();
        assert!(matches!(c.validate(), Err(GatewayError::HttpRequest(_))));
    }
    let mut c = config();
    c.routes[0].max_response_bytes = 0;
    assert!(matches!(c.validate(), Err(GatewayError::HttpRequest(_))));
}

#[test]
fn public_http_validation_refuses_invalid_backend_configuration() {
    let mut c: HttpGatewayConfig = serde_json::from_value(json!({
        "service": "http", "method": "fetch",
        "backends": {"model": {
            "models": ["example"], "credential": "upstream",
            "routes": [{"path": "/v1/responses", "method": "POST", "url": "https://api.example.com/v1/responses"}],
        }},
    })).unwrap();
    c.validate().unwrap();
    c.routes = config().routes;
    assert!(matches!(
        c.validate(),
        Err(GatewayError::Config(GatewayConfigError::RouteMode))
    ));
    c.routes.clear();
    let backend = c.backends.get_mut("model").unwrap();
    backend.routes[0].credential = Some("another".into());
    assert!(matches!(
        c.validate(),
        Err(GatewayError::Config(GatewayConfigError::BackendCredential))
    ));
    let backend = c.backends.get_mut("model").unwrap();
    backend.routes[0].credential = None;
    backend.models.clear();
    assert!(matches!(
        c.validate(),
        Err(GatewayError::Config(GatewayConfigError::ModelNames))
    ));
}
