//! Outbound, authenticated light-client RPC serving for validators.

use crate::domain::PrivateKey;
use crate::genesis::Genesis;
use crate::{LightClient, LightClientRpc, LightClientRpcState, serve_light_client_transport};
use commonware_codec::Encode;
use commonware_cryptography::Signer;
use hellas_wire::PeerIdentity;
use hellas_wire::relay_auth::{
    NETWORK_HEADER, NONCE_BYTES, NONCE_HEADER, RelayAdmission, RelayAdmissionError,
    SIGNATURE_HEADER, SIGNING_NAMESPACE, TIMESTAMP_HEADER, VALIDATOR_HEADER,
};
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::{HeaderValue, Request};

#[derive(Debug, thiserror::Error)]
pub enum RelayConnectError {
    #[error("invalid genesis document: {0}")]
    Genesis(#[from] crate::genesis::GenesisError),
    #[error("validator identity is not in the genesis committee")]
    NotInCommittee,
    #[error("invalid relay URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("relay URL must be a ws(s) origin without credentials, query, or fragment")]
    InvalidOrigin,
    #[error("failed to construct WebSocket request: {0}")]
    Request(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("WebSocket request did not contain a canonical authority or path")]
    MissingRequestTarget,
    #[error("invalid relay admission: {0}")]
    Admission(#[from] RelayAdmissionError),
    #[error("invalid relay header: {0}")]
    Header(#[from] tokio_tungstenite::tungstenite::http::header::InvalidHeaderValue),
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[error("relay WebSocket failed: {0}")]
    WebSocket(#[from] hellas_wire::ws::WsError),
    #[error("light-client relay serving failed: {0}")]
    Serve(String),
}

/// Construct one signed `/relay/:validator` WebSocket upgrade request.
pub fn authenticated_relay_request(
    relay_origin: &str,
    genesis: &Genesis,
    private_key: &PrivateKey,
    timestamp_ms: u64,
    nonce: [u8; NONCE_BYTES],
) -> Result<Request<()>, RelayConnectError> {
    genesis.validate()?;
    let public_key = private_key.public_key();
    let public_key_bytes: [u8; 32] = public_key
        .as_ref()
        .try_into()
        .expect("ed25519 public key has a fixed 32-byte representation");
    let public_key_hex = hex::encode(public_key.encode());
    if genesis.validator(&public_key_hex).is_none() {
        return Err(RelayConnectError::NotInCommittee);
    }

    let mut url = url::Url::parse(relay_origin)?;
    if !matches!(url.scheme(), "ws" | "wss")
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(RelayConnectError::InvalidOrigin);
    }
    url.set_path(&format!("/relay/{public_key_hex}"));

    let mut request = url.as_str().into_client_request()?;
    let authority = request
        .uri()
        .authority()
        .map(|authority| authority.as_str())
        .ok_or(RelayConnectError::MissingRequestTarget)?;
    let path = request.uri().path();
    let admission = RelayAdmission::new(
        &genesis.network_id,
        authority,
        path,
        PeerIdentity(public_key_bytes),
        timestamp_ms,
        nonce,
    )?;
    let signature = private_key.sign(SIGNING_NAMESPACE, &admission.message());

    let headers = request.headers_mut();
    headers.insert(NETWORK_HEADER, HeaderValue::from_str(&genesis.network_id)?);
    headers.insert(VALIDATOR_HEADER, HeaderValue::from_str(&public_key_hex)?);
    headers.insert(
        TIMESTAMP_HEADER,
        HeaderValue::from_str(&timestamp_ms.to_string())?,
    );
    headers.insert(NONCE_HEADER, HeaderValue::from_str(&hex::encode(nonce))?);
    headers.insert(
        SIGNATURE_HEADER,
        HeaderValue::from_str(&hex::encode(signature.encode()))?,
    );
    Ok(request)
}

/// Dial one relay and serve the typed light-client API until it disconnects.
pub async fn serve_light_client_relay<C>(
    relay_origin: &str,
    genesis: &Genesis,
    private_key: &PrivateKey,
    client: C,
    activity_tx: broadcast::Sender<crate::ConsensusActivity>,
    rpc_state: LightClientRpcState,
) -> Result<(), RelayConnectError>
where
    C: LightClient,
{
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| RelayConnectError::Clock)?
        .as_millis()
        .try_into()
        .map_err(|_| RelayConnectError::Clock)?;
    let nonce = rand::random();
    let request =
        authenticated_relay_request(relay_origin, genesis, private_key, timestamp_ms, nonce)?;
    let transport = hellas_wire::ws::connect_server(request).await?;
    serve_light_client_transport(
        transport,
        LightClientRpc::with_state(client, activity_tx, rpc_state),
    )
    .await
    .map_err(|error| RelayConnectError::Serve(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::{GENESIS_SCHEMA_VERSION, GenesisValidator};
    use commonware_cryptography::ed25519;
    use ed25519_dalek::Verifier as _;
    use hellas_wire::relay_auth::{
        NETWORK_HEADER, NONCE_HEADER, SIGNATURE_HEADER, TIMESTAMP_HEADER, VALIDATOR_HEADER,
    };

    fn genesis(private_key: &ed25519::PrivateKey) -> Genesis {
        Genesis {
            schema_version: GENESIS_SCHEMA_VERSION,
            network_id: crate::genesis::HELLAS_DEVNET_1_ID.to_string(),
            validators: vec![GenesisValidator {
                public_key: hex::encode(private_key.public_key().encode()),
                label: "validator-a".to_string(),
            }],
            allocations: Vec::new(),
        }
    }

    #[test]
    fn commonware_signature_verifies_as_raw_ed25519_at_the_relay() {
        let private_key = ed25519::PrivateKey::from_seed(7);
        let genesis = genesis(&private_key);
        let request = authenticated_relay_request(
            "wss://relay.example",
            &genesis,
            &private_key,
            1_725_000_000_000,
            [0x5a; NONCE_BYTES],
        )
        .unwrap();

        let headers = request.headers();
        assert_eq!(headers[NETWORK_HEADER], genesis.network_id);
        let public_key_hex = headers[VALIDATOR_HEADER].to_str().unwrap();
        assert_eq!(
            public_key_hex,
            "10a1860ee01fa0dad17543b41fa56f4e098708100019f5f7cec1fc59b2cc0fec"
        );
        assert_eq!(request.uri().path(), format!("/relay/{public_key_hex}"));
        let public_key_bytes: [u8; 32] = hex::decode(public_key_hex).unwrap().try_into().unwrap();
        let timestamp_ms = headers[TIMESTAMP_HEADER].to_str().unwrap().parse().unwrap();
        let nonce: [u8; NONCE_BYTES] = hex::decode(headers[NONCE_HEADER].to_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let admission = RelayAdmission::new(
            &genesis.network_id,
            request.uri().authority().unwrap().as_str(),
            request.uri().path(),
            PeerIdentity(public_key_bytes),
            timestamp_ms,
            nonce,
        )
        .unwrap();
        let signature_bytes: [u8; 64] = hex::decode(headers[SIGNATURE_HEADER].to_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            hex::encode(signature_bytes),
            "9b62b03a2214d15382dbd48439ff22ead585b655daa10caf5ff003db9d945a79736faeb0d9df84de1ba412a44cf952999f01fcb735df7f0ffc21bf0151eb9508"
        );
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

        verifying_key
            .verify(&admission.signed_payload(), &signature)
            .unwrap();
    }

    #[test]
    fn request_rejects_nonmember_and_nonorigin_urls() {
        let member = ed25519::PrivateKey::from_seed(7);
        let other = ed25519::PrivateKey::from_seed(8);
        let genesis = genesis(&member);
        assert!(matches!(
            authenticated_relay_request(
                "wss://relay.example",
                &genesis,
                &other,
                1,
                [0; NONCE_BYTES],
            ),
            Err(RelayConnectError::NotInCommittee)
        ));
        for url in [
            "https://relay.example",
            "wss://relay.example/prefix",
            "wss://relay.example?query=yes",
            "wss://user@relay.example",
        ] {
            assert!(matches!(
                authenticated_relay_request(url, &genesis, &member, 1, [0; NONCE_BYTES]),
                Err(RelayConnectError::InvalidOrigin)
            ));
        }
    }
}
