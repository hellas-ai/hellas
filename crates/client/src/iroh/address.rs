//! The one string a buyer learns out of band to reach and trust a provider.
use super::ProviderTrustAnchor;
use crate::{ClientError, ClientResult};
use hellas_auth::PublicKey;
use hellas_rpc::{Assurance, ContentId, ProviderEnrollmentBundle};
use std::{fmt, str::FromStr};

/// `ENROLLMENT_ID@NODE_ID`: the content id of the provider's enrollment bundle
/// and the transport key that bundle's root-signed statement binds. Every
/// connection to the provider must present exactly this enrollment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderAddress {
    pub enrollment: ContentId,
    pub node: ::iroh::EndpointId,
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderAddressError {
    #[error("provider address must be ENROLLMENT_ID@NODE_ID")]
    Form,
    #[error("invalid enrollment ID in provider address ENROLLMENT_ID@NODE_ID")]
    Enrollment,
    #[error("invalid node ID in provider address ENROLLMENT_ID@NODE_ID")]
    Node,
}

impl ProviderAddress {
    /// The address of the provider holding `bundle`.
    pub fn of(bundle: &ProviderEnrollmentBundle) -> ClientResult<Self> {
        let PublicKey::Ed25519(node) = bundle.genesis.statement.transport_public_key else {
            return Err(ClientError::protocol(
                "provider enrollment transport key is not an Ed25519 node ID",
            ));
        };
        Ok(Self {
            enrollment: bundle.content_id(),
            node: ::iroh::EndpointId::from_bytes(&node)
                .map_err(|e| ClientError::source("invalid provider node ID", e))?,
        })
    }

    /// The trust every connection to this provider requires. An Apple provider
    /// also needs its independent approval, which must name this enrollment.
    pub fn trust(
        &self,
        assurance: Assurance,
        approval: Option<&ProviderTrustAnchor>,
    ) -> ClientResult<ProviderTrustAnchor> {
        match approval {
            Some(approval) if approval.expected_genesis != self.enrollment => Err(
                ClientError::protocol("provider approval names a different enrollment"),
            ),
            Some(approval) if approval.required_assurance != assurance => Err(
                ClientError::protocol("provider approval assurance differs from request"),
            ),
            Some(approval) => Ok(approval.clone()),
            None if assurance == Assurance::ProducerSigned => Ok(ProviderTrustAnchor {
                expected_genesis: self.enrollment,
                required_assurance: assurance,
                apple_app_attest: None,
            }),
            None => Err(ClientError::protocol(
                "Apple assurance requires an independent provider approval",
            )),
        }
    }
}

impl fmt::Display for ProviderAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}@{}", self.enrollment, self.node)
    }
}

impl FromStr for ProviderAddress {
    type Err = ProviderAddressError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (enrollment, node) = value.split_once('@').ok_or(ProviderAddressError::Form)?;
        Ok(Self {
            enrollment: enrollment
                .parse()
                .map_err(|_| ProviderAddressError::Enrollment)?,
            node: node.parse().map_err(|_| ProviderAddressError::Node)?,
        })
    }
}

impl serde::Serialize for ProviderAddress {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for ProviderAddress {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> ProviderAddress {
        ProviderAddress {
            enrollment: ContentId::from_bytes([7; 32]),
            node: ::iroh::SecretKey::from_bytes(&[4; 32]).public(),
        }
    }

    #[test]
    fn address_round_trips_through_its_one_string_form() {
        let address = address();
        let text = address.to_string();
        assert_eq!(text, format!("{}@{}", address.enrollment, address.node));
        assert_eq!(text.parse::<ProviderAddress>().unwrap(), address);
        let json = serde_json::to_string(&address).unwrap();
        assert_eq!(json, format!("\"{text}\""));
        assert_eq!(
            serde_json::from_str::<ProviderAddress>(&json).unwrap(),
            address
        );
    }

    #[test]
    fn a_node_id_alone_is_not_an_address() {
        let address = address();
        assert!(matches!(
            address.node.to_string().parse::<ProviderAddress>(),
            Err(ProviderAddressError::Form)
        ));
        for invalid in [
            format!("{}@", address.enrollment),
            format!("@{}", address.node),
            format!("{}@{}@1.2.3.4:5", address.enrollment, address.node),
        ] {
            assert!(invalid.parse::<ProviderAddress>().is_err(), "{invalid}");
        }
    }

    #[test]
    fn trust_pins_the_addressed_enrollment() {
        let address = address();
        let trust = address.trust(Assurance::ProducerSigned, None).unwrap();
        assert_eq!(trust.expected_genesis, address.enrollment);
        assert!(trust.apple_app_attest.is_none());
        assert!(address.trust(Assurance::AppleAppAttest, None).is_err());
        let mut approval = trust.clone();
        assert_eq!(
            address
                .trust(Assurance::ProducerSigned, Some(&approval))
                .unwrap(),
            approval
        );
        assert!(
            address
                .trust(Assurance::AppleAppAttest, Some(&approval))
                .is_err()
        );
        approval.expected_genesis = ContentId::from_bytes([8; 32]);
        assert!(
            address
                .trust(Assurance::ProducerSigned, Some(&approval))
                .is_err()
        );
    }
}
