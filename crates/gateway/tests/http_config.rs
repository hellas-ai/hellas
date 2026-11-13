use hellas_gateway::{GatewayConfigError, GatewayError, HttpRoute};
use serde_json::json;

fn config() -> HttpRoute {
    serde_json::from_value(json!({"path":"/v1/responses","method":"POST","url":"https://api.example.com/v1/responses"})).unwrap()
}

#[test]
fn public_http_validation_accepts_valid_routes_and_refuses_invalid_configurations() {
    let c = config();
    c.validate().unwrap();
    for path in ["relative", "/path?query", "/path#fragment", "/{param}"] {
        let mut c = config();
        c.path = path.into();
        assert!(matches!(
            c.validate(),
            Err(GatewayError::Config(GatewayConfigError::RoutePath))
        ));
    }
    let mut c = config();
    c.headers
        .push(("authorization".into(), "inline-secret".into()));
    assert!(matches!(
        c.validate(),
        Err(GatewayError::Config(GatewayConfigError::CredentialHeader))
    ));
    for url in ["http://api.example.com", "not a URL"] {
        let mut c = config();
        c.url = url.into();
        assert!(matches!(c.validate(), Err(GatewayError::HttpRequest(_))));
    }
    let mut c = config();
    c.max_response_bytes = 0;
    assert!(matches!(c.validate(), Err(GatewayError::HttpRequest(_))));
}

#[test]
fn http_routes_cannot_name_provider_credentials() {
    let mut route = serde_json::to_value(config()).unwrap();
    assert!(route.get("credential").is_none());
    route["credential"] = "provider-account".into();
    assert!(serde_json::from_value::<HttpRoute>(route).is_err());
}
