//! Versioned Fetch execution semantics, carried by resources and signed inputs.
//! A content hash authenticates these terms only after independent provider trust
//! checks. Descriptors never load code or authorize an unknown schema interpreter.

use super::value::{CanonicalDecodeError, CanonicalDecoder};
use crate::{Application, ContentId, DagCborEncoder, ProgramManifest};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

pub const FETCH_EVALUATOR: &str = "hellas/fetch-0.0.2";
const DOMAIN: &str = "hellas.fetch.contract.v1";
pub const MAX_FETCH_CONTRACT_BYTES: usize = 8 * 1024;

/// The compiled request/result schema pairs understood by this client release.
/// Driver and adaptor identities remain exact, independently committed terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchSchema {
    /// Signed HTTPS request and canonical HTTP response events.
    HttpV1,
    /// Stateless bounded Responses JSON and canonical output events.
    StatelessResponsesV1,
    /// Responses item JSON and canonical output events, without an output cap.
    ResponsesItemsV1,
}

impl FetchSchema {
    pub const fn id(self) -> &'static str {
        match self {
            Self::HttpV1 => "hellas.fetch.schema.http.v1",
            Self::StatelessResponsesV1 => "hellas.fetch.schema.stateless-responses.v1",
            Self::ResponsesItemsV1 => "hellas.fetch.schema.responses-items.v1",
        }
    }

    fn decode(id: &str) -> Result<Self, CanonicalDecodeError> {
        [
            Self::HttpV1,
            Self::StatelessResponsesV1,
            Self::ResponsesItemsV1,
        ]
        .into_iter()
        .find(|schema| schema.id() == id)
        .ok_or_else(|| invalid("unsupported Fetch request/result schema"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FetchEgress {
    /// URL and TLS settings are in the caller's signed HTTPS request.
    RequestHttps,
    /// The adapter permits only this exact HTTPS URL, with no redirects.
    FixedHttps(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchContract {
    application: Application,
    schema: FetchSchema,
    driver: String,
    egress: FetchEgress,
}

impl FetchContract {
    pub fn new(
        adaptor: impl Into<String>,
        schema: FetchSchema,
        driver: impl Into<String>,
        egress: FetchEgress,
    ) -> Result<Self, CanonicalDecodeError> {
        let application = Application::new(FETCH_EVALUATOR, adaptor)
            .map_err(|error| invalid(error.to_string()))?;
        let driver = driver.into();
        if driver.is_empty() || driver.len() > 1024 {
            return Err(invalid("Fetch driver identity must contain 1..=1024 bytes"));
        }
        match (&egress, schema) {
            (FetchEgress::RequestHttps, FetchSchema::HttpV1) => {}
            (FetchEgress::RequestHttps, _) => {
                return Err(invalid(
                    "only the HTTP schema permits request-selected egress",
                ));
            }
            (FetchEgress::FixedHttps(endpoint), _) => {
                if endpoint.len() > 2048 {
                    return Err(invalid("Fetch endpoint exceeds 2048 bytes"));
                }
                let url =
                    url::Url::parse(endpoint).map_err(|_| invalid("invalid Fetch endpoint"))?;
                if url.scheme() != "https"
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || url.as_str() != endpoint
                {
                    return Err(invalid(
                        "Fetch endpoint must be an exact HTTPS URL without credentials, query or fragment",
                    ));
                }
            }
        }
        Ok(Self {
            application,
            schema,
            driver,
            egress,
        })
    }

    pub fn http() -> Result<Self, CanonicalDecodeError> {
        Self::new(
            "http-0.0.1",
            FetchSchema::HttpV1,
            "https-request-roots-and-spki-no-redirect-0.0.1",
            FetchEgress::RequestHttps,
        )
    }

    pub fn adaptor(&self) -> &str {
        self.application.adaptor()
    }
    pub const fn schema(&self) -> FetchSchema {
        self.schema
    }
    pub fn driver(&self) -> &str {
        &self.driver
    }
    pub const fn egress(&self) -> &FetchEgress {
        &self.egress
    }

    /// Exact DAG-CBOR `[domain, adaptor, schema, driver, egress-kind, endpoint]`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = DagCborEncoder::new();
        encoder.array(6);
        encoder.str(DOMAIN);
        encoder.str(self.adaptor());
        encoder.str(self.schema.id());
        encoder.str(&self.driver);
        match &self.egress {
            FetchEgress::RequestHttps => {
                encoder.u64(0);
                encoder.str("");
            }
            FetchEgress::FixedHttps(endpoint) => {
                encoder.u64(1);
                encoder.str(endpoint);
            }
        }
        encoder.into_bytes()
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalDecodeError> {
        if bytes.len() > MAX_FETCH_CONTRACT_BYTES {
            return Err(invalid("Fetch contract exceeds byte limit"));
        }
        let mut decoder = CanonicalDecoder::new(bytes);
        decoder.array_exact(6)?;
        decoder.expect_str(DOMAIN)?;
        let adaptor = decoder.str()?;
        let schema = FetchSchema::decode(decoder.str()?)?;
        let driver = decoder.str()?;
        let kind = decoder.u64()?;
        let endpoint = decoder.str()?;
        let egress = match (kind, endpoint) {
            (0, "") => FetchEgress::RequestHttps,
            (1, endpoint) => FetchEgress::FixedHttps(endpoint.into()),
            _ => return Err(invalid("unknown Fetch egress contract")),
        };
        decoder.finish()?;
        let contract = Self::new(adaptor, schema, driver, egress)?;
        if contract.canonical_bytes() != bytes {
            return Err(invalid("noncanonical Fetch contract"));
        }
        Ok(contract)
    }

    pub fn content_id(&self) -> ContentId {
        ContentId::hash(&self.canonical_bytes())
    }
    pub fn manifest(&self) -> ProgramManifest {
        ProgramManifest::new(self.application.clone(), self.content_id())
    }
    pub fn manifest_id(&self) -> ContentId {
        self.manifest().content_id()
    }
}

fn invalid(message: impl Into<String>) -> CanonicalDecodeError {
    CanonicalDecodeError::new(message)
}

impl Serialize for FetchContract {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        let mut value = serializer.serialize_struct("FetchContract", 4)?;
        value.serialize_field("adaptor", self.adaptor())?;
        value.serialize_field("schema", &self.schema)?;
        value.serialize_field("driver", &self.driver)?;
        value.serialize_field("egress", &self.egress)?;
        value.end()
    }
}

impl<'de> Deserialize<'de> for FetchContract {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            adaptor: String,
            schema: FetchSchema,
            driver: String,
            egress: FetchEgress,
        }
        let value = Fields::deserialize(deserializer)?;
        Self::new(value.adaptor, value.schema, value.driver, value.egress).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(adaptor: &str, driver: &str, endpoint: &str) -> FetchContract {
        FetchContract::new(
            adaptor,
            FetchSchema::StatelessResponsesV1,
            driver,
            FetchEgress::FixedHttps(endpoint.into()),
        )
        .unwrap()
    }

    #[test]
    fn generic_http_contract_has_fixed_bytes_and_manifest() {
        let contract = FetchContract::http().unwrap();
        let hex: String = contract
            .canonical_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            hex,
            "86781868656c6c61732e66657463682e636f6e74726163742e76316a687474702d302e302e31781b68656c6c61732e66657463682e736368656d612e687474702e7631782e68747470732d726571756573742d726f6f74732d616e642d73706b692d6e6f2d72656469726563742d302e302e310060"
        );
        assert_eq!(
            contract.manifest_id().to_string(),
            "5c36f02c7d67c5c6ed5c83528b0cd6552bd3d2ed84a544e2b47a68e3f4b5854e"
        );
    }

    #[test]
    fn contract_commits_every_execution_term_without_a_vendor_registry() {
        let original = descriptor(
            "example-adapter-1",
            "driver-1",
            "https://example.com/v1/responses",
        );
        for contract in [
            FetchContract::http().unwrap(),
            original.clone(),
            descriptor(
                "another-adapter-1",
                "driver-1",
                "https://example.com/v1/responses",
            ),
            descriptor(
                "example-adapter-1",
                "driver-2",
                "https://example.com/v1/responses",
            ),
            descriptor(
                "example-adapter-1",
                "driver-1",
                "https://example.net/v1/responses",
            ),
        ] {
            let bytes = contract.canonical_bytes();
            assert_eq!(
                FetchContract::from_canonical_bytes(&bytes).unwrap(),
                contract
            );
            assert_eq!(contract.content_id(), ContentId::hash(&bytes));
            assert_eq!(contract.manifest().root(), contract.content_id());
            assert_eq!(
                contract.manifest().application().evaluator(),
                FETCH_EVALUATOR
            );
            #[cfg(feature = "fetch")]
            {
                let json = serde_json::to_vec(&contract).unwrap();
                assert_eq!(
                    serde_json::from_slice::<FetchContract>(&json).unwrap(),
                    contract
                );
            }
            if contract != original {
                assert_ne!(contract.manifest_id(), original.manifest_id());
            }
        }
        let different_schema = FetchContract::new(
            original.adaptor(),
            FetchSchema::ResponsesItemsV1,
            original.driver(),
            original.egress().clone(),
        )
        .unwrap();
        assert_ne!(different_schema.manifest_id(), original.manifest_id());
    }

    #[test]
    fn unknown_schemas_and_noncanonical_contracts_are_rejected() {
        let original = FetchContract::http().unwrap();
        let mut unknown = DagCborEncoder::new();
        unknown.array(6);
        unknown.str(DOMAIN);
        unknown.str(original.adaptor());
        unknown.str("unrecognized-request-and-result-v1");
        unknown.str(original.driver());
        unknown.u64(0);
        unknown.str("");
        assert!(FetchContract::from_canonical_bytes(&unknown.into_bytes()).is_err());
        let bytes = original.canonical_bytes();
        for end in 0..bytes.len() {
            assert!(FetchContract::from_canonical_bytes(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(FetchContract::from_canonical_bytes(&trailing).is_err());
        let mut nonminimal = vec![0x98, 6];
        nonminimal.extend_from_slice(&bytes[1..]);
        assert!(FetchContract::from_canonical_bytes(&nonminimal).is_err());
        assert!(
            FetchContract::from_canonical_bytes(&vec![0; MAX_FETCH_CONTRACT_BYTES + 1]).is_err()
        );
        #[cfg(feature = "fetch")]
        {
            let mut json = serde_json::to_value(&original).unwrap();
            json["schema"] = "future_schema".into();
            assert!(serde_json::from_value::<FetchContract>(json).is_err());
        }
    }

    #[test]
    fn egress_is_exact_and_cannot_hide_credentials_or_request_selected_urls() {
        for endpoint in [
            "http://example.com/",
            "https://user@example.com/",
            "https://example.com/?key=secret",
            "https://example.com/#fragment",
            "https://EXAMPLE.com/",
            "https://example.com:443/",
        ] {
            assert!(
                FetchContract::new(
                    "adapter",
                    FetchSchema::StatelessResponsesV1,
                    "driver",
                    FetchEgress::FixedHttps(endpoint.into())
                )
                .is_err(),
                "{endpoint}"
            );
        }
        assert!(
            FetchContract::new(
                "adapter",
                FetchSchema::StatelessResponsesV1,
                "driver",
                FetchEgress::RequestHttps
            )
            .is_err()
        );
        assert!(
            FetchContract::new(
                "adapter",
                FetchSchema::HttpV1,
                "",
                FetchEgress::RequestHttps
            )
            .is_err()
        );
        assert!(
            FetchContract::new("", FetchSchema::HttpV1, "driver", FetchEgress::RequestHttps)
                .is_err()
        );
        #[cfg(feature = "fetch")]
        {
            let mut json = serde_json::to_value(FetchContract::http().unwrap()).unwrap();
            json["plugin"] = "untrusted code".into();
            assert!(serde_json::from_value::<FetchContract>(json).is_err());
        }
    }
}
