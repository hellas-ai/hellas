//! Canonical validator-to-relay admission messages.
//!
//! This module owns bytes, not keys. Validators sign [`RelayAdmission::message`]
//! with [`SIGNING_NAMESPACE`], while relays verify the raw Ed25519 signature
//! against [`RelayAdmission::signed_payload`]. Keeping both constructions here
//! prevents native nodes and edge runtimes from inventing subtly different
//! authentication formats.

use crate::PeerIdentity;

/// Commonware signing namespace for relay admission signatures.
pub const SIGNING_NAMESPACE: &[u8] = b"hellas/relay-admission/v1";

pub const NETWORK_HEADER: &str = "x-hellas-network";
pub const VALIDATOR_HEADER: &str = "x-hellas-validator";
pub const TIMESTAMP_HEADER: &str = "x-hellas-timestamp-ms";
pub const NONCE_HEADER: &str = "x-hellas-nonce";
pub const SIGNATURE_HEADER: &str = "x-hellas-signature";

pub const NONCE_BYTES: usize = 16;
pub const SIGNATURE_BYTES: usize = 64;
pub const MAX_CLOCK_SKEW_MS: u64 = 60_000;
pub const REPLAY_RETENTION_MS: u64 = MAX_CLOCK_SKEW_MS * 2;

const METHOD: &[u8] = b"GET";
const MAX_NETWORK_ID_BYTES: usize = 63;
const MAX_AUTHORITY_BYTES: usize = 255;
const MAX_PATH_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayAdmission<'a> {
    pub network_id: &'a str,
    pub authority: &'a str,
    pub path: &'a str,
    pub validator: PeerIdentity,
    pub timestamp_ms: u64,
    pub nonce: [u8; NONCE_BYTES],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RelayAdmissionError {
    #[error("network id must be 1..={MAX_NETWORK_ID_BYTES} lowercase ASCII token bytes")]
    InvalidNetworkId,
    #[error("authority must be 1..={MAX_AUTHORITY_BYTES} canonical ASCII bytes")]
    InvalidAuthority,
    #[error("path must be an absolute canonical path of at most {MAX_PATH_BYTES} bytes")]
    InvalidPath,
}

impl<'a> RelayAdmission<'a> {
    pub fn new(
        network_id: &'a str,
        authority: &'a str,
        path: &'a str,
        validator: PeerIdentity,
        timestamp_ms: u64,
        nonce: [u8; NONCE_BYTES],
    ) -> Result<Self, RelayAdmissionError> {
        if network_id.is_empty()
            || network_id.len() > MAX_NETWORK_ID_BYTES
            || !network_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(RelayAdmissionError::InvalidNetworkId);
        }
        if authority.is_empty()
            || authority.len() > MAX_AUTHORITY_BYTES
            || !authority.is_ascii()
            || authority.bytes().any(|byte| {
                byte.is_ascii_uppercase()
                    || byte.is_ascii_whitespace()
                    || matches!(byte, b'/' | b'?' | b'#' | b'@')
            })
        {
            return Err(RelayAdmissionError::InvalidAuthority);
        }
        if !path.starts_with('/')
            || path.len() > MAX_PATH_BYTES
            || !path.is_ascii()
            || path.bytes().any(|byte| matches!(byte, b'?' | b'#'))
        {
            return Err(RelayAdmissionError::InvalidPath);
        }
        Ok(Self {
            network_id,
            authority,
            path,
            validator,
            timestamp_ms,
            nonce,
        })
    }

    /// Message passed to Commonware's `Signer::sign(SIGNING_NAMESPACE, ...)`.
    ///
    /// Layout, in order:
    /// `GET | u16(authority len) | authority | u16(path len) | path |
    /// u16(network len) | network | validator[32] | timestamp_ms(u64 BE) |
    /// nonce[16]`.
    #[must_use]
    pub fn message(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            METHOD.len()
                + 2
                + self.authority.len()
                + 2
                + self.path.len()
                + 2
                + self.network_id.len()
                + self.validator.0.len()
                + size_of::<u64>()
                + self.nonce.len(),
        );
        bytes.extend_from_slice(METHOD);
        push_str(&mut bytes, self.authority);
        push_str(&mut bytes, self.path);
        push_str(&mut bytes, self.network_id);
        bytes.extend_from_slice(&self.validator.0);
        bytes.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes
    }

    /// Exact bytes verified by a raw Ed25519 implementation.
    ///
    /// Commonware domain-separates signatures as
    /// `varint(namespace.len) | namespace | message`. The namespace is shorter
    /// than 128 bytes, so its canonical varint is the single prefix byte used
    /// below.
    #[must_use]
    pub fn signed_payload(&self) -> Vec<u8> {
        const {
            assert!(SIGNING_NAMESPACE.len() < 128);
        }
        let message = self.message();
        let mut bytes = Vec::with_capacity(1 + SIGNING_NAMESPACE.len() + message.len());
        bytes.push(SIGNING_NAMESPACE.len() as u8);
        bytes.extend_from_slice(SIGNING_NAMESPACE);
        bytes.extend_from_slice(&message);
        bytes
    }
}

fn push_str(bytes: &mut Vec<u8>, value: &str) {
    let len = u16::try_from(value.len()).expect("validated relay admission field length");
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> RelayAdmission<'static> {
        RelayAdmission::new(
            "hellas-devnet-1",
            "relay.example:8443",
            "/relay/validator",
            PeerIdentity([0x42; 32]),
            0x0102_0304_0506_0708,
            [0xa5; NONCE_BYTES],
        )
        .unwrap()
    }

    #[test]
    fn canonical_message_binds_every_routing_field() {
        let original = fixture();
        for changed in [
            RelayAdmission {
                authority: "other.example",
                ..original
            },
            RelayAdmission {
                path: "/relay/other",
                ..original
            },
            RelayAdmission {
                network_id: "another-network",
                ..original
            },
            RelayAdmission {
                validator: PeerIdentity([0x43; 32]),
                ..original
            },
            RelayAdmission {
                timestamp_ms: original.timestamp_ms + 1,
                ..original
            },
            RelayAdmission {
                nonce: [0xa6; NONCE_BYTES],
                ..original
            },
        ] {
            assert_ne!(original.signed_payload(), changed.signed_payload());
        }
    }

    #[test]
    fn signed_payload_uses_commonware_namespace_framing() {
        let admission = fixture();
        let payload = admission.signed_payload();
        assert_eq!(payload[0] as usize, SIGNING_NAMESPACE.len());
        assert_eq!(&payload[1..=SIGNING_NAMESPACE.len()], SIGNING_NAMESPACE);
        assert_eq!(&payload[1 + SIGNING_NAMESPACE.len()..], admission.message());
    }

    #[test]
    fn rejects_noncanonical_routing_strings() {
        let base = fixture();
        for (network, authority, path) in [
            ("Hellas", base.authority, base.path),
            ("", base.authority, base.path),
            (base.network_id, "Relay.Example", base.path),
            (base.network_id, "user@relay.example", base.path),
            (base.network_id, base.authority, "relay/validator"),
            (base.network_id, base.authority, "/relay/validator?x=1"),
        ] {
            assert!(
                RelayAdmission::new(
                    network,
                    authority,
                    path,
                    base.validator,
                    base.timestamp_ms,
                    base.nonce,
                )
                .is_err()
            );
        }
    }
}
