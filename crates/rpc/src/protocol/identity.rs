//! A provider's founding identity statement.
//!
//! # What "provider genesis" means
//!
//! The same thing a chain's genesis means, for a different subject. A
//! chain's genesis is the founding document a network's whole history
//! chains back to; a *provider's* genesis is the founding statement one
//! provider installation's whole key hierarchy chains back to. Both are
//! self-authenticating roots, and neither can be reissued without
//! becoming a different thing.
//!
//! It is emitted once, when a provider installation first starts, and
//! it binds together:
//!
//!   - the hardware root that vouches for the installation
//!     ([`RootKind`] + `root_public_key`) — Secure Enclave, or a plain
//!     software key on a machine without one;
//!   - `producer_public_key`, the key that signs the provider's work;
//!   - `transport_public_key`, the key that terminates its connections;
//!   - `platform_credential`, its Apple App Attest registration if it
//!     has one;
//!   - `installation_nonce`, which makes this installation distinct
//!     from a reinstall on the same hardware.
//!
//! [`RootProof`] is the root key's signature over that statement, which
//! is what makes it self-authenticating: the root asserts "these are my
//! keys", and every later signature the provider makes traces back
//! here.
//!
//! # How a requester uses it
//!
//! [`ProviderEnrollmentBundle::content_id`] is the Xet hash of the
//! whole artifact. A requester pins that id **out of band** — the CLI
//! flag is `--provider <content-id>` — and refuses to run against
//! anything that does not hash to it. Pinning out of band is the point:
//! a provider that could hand you its own identity on connect could
//! hand you any identity.
//!
//! # Deliberately unrelated to the network
//!
//! This has nothing to do with which *chain* anything settles on. A
//! paying client sets both, and they answer different questions:
//! `--network` says which chain the payment channel opens on;
//! `--provider` says whose work it will pay for. The two are
//! independent trust decisions about two different parties, and the
//! shared word "genesis" in the type names below is a statement about
//! their shape, not a connection between them.

use crate::{ContentId, DagCborEncoder, PublicKey, Signature, SignatureKind};

/// The kind of hardware root vouching for a provider installation.
///
/// Discriminants are wire values and must not be reordered. `2` was a
/// TPM 2.0 attestation key: never implemented on either side, so it was
/// removed, and a statement carrying it decodes as an unknown root kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RootKind {
    /// Apple Secure Enclave, attested through App Attest.
    SecureEnclave = 1,
    /// A plain software key. No hardware claim is made: this is for
    /// machines with neither of the above, and a requester that cares
    /// about hardware backing must refuse it.
    Software = 3,
}

/// A platform attestation credential the provider registered, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformCredential {
    /// No platform credential; the root proof stands alone.
    Absent,
    /// Registered, pinned by the content id of its enrollment.
    Registered(ContentId),
}

/// What one provider installation asserts about itself, once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderGenesisStatement {
    pub root_kind: RootKind,
    pub root_public_key: PublicKey,
    pub producer_public_key: PublicKey,
    pub transport_public_key: PublicKey,
    pub platform_credential: PlatformCredential,
    pub installation_nonce: [u8; 32],
}

/// The root key's signature over a [`ProviderGenesisStatement`]. This
/// is what makes the statement self-authenticating rather than a
/// claim anyone could make.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootProof {
    /// Apple attestation object over the statement.
    AppleAppAttest(Vec<u8>),
    /// Software root-key signature. Carries no hardware claim.
    Software(Signature),
}

/// A provider's founding statement together with the root proof that
/// authenticates it. The two travel as one; a statement without its
/// proof asserts nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedProviderGenesis {
    pub statement: ProviderGenesisStatement,
    pub root_proof: RootProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppleAppAttestEnrollment {
    pub attestation_object: Vec<u8>,
    pub client_data_hash: [u8; 32],
    pub validation_time: u64,
}

/// The platform enrollment evidence shipped alongside the genesis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlatformEnrollment {
    /// None; the provider registered no platform credential.
    Absent,
    /// Apple App Attest enrollment, retained in full so a requester can
    /// re-register it against its own pinned Apple policy.
    AppleAppAttest(AppleAppAttestEnrollment),
}

/// The complete, out-of-band-pinned provider enrollment artifact.
///
/// Apple enrollment retains the original attestation object and challenge
/// hash so a requester can independently register the credential against its
/// pinned Apple policy. `validation_time` records when the short-lived
/// enrollment certificate was received and is part of the pinned commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderEnrollmentBundle {
    pub genesis: SignedProviderGenesis,
    pub platform: PlatformEnrollment,
}

impl ProviderGenesisStatement {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut e = DagCborEncoder::new();
        encode_statement(&mut e, self);
        e.into_bytes()
    }
}

impl SignedProviderGenesis {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut e = DagCborEncoder::new();
        encode_signed(&mut e, self);
        e.into_bytes()
    }
}

impl ProviderEnrollmentBundle {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut e = DagCborEncoder::new();
        e.array(3);
        e.str("hellas.provider.enrollment.bundle.v1");
        encode_signed(&mut e, &self.genesis);
        encode_platform_enrollment(&mut e, &self.platform);
        e.into_bytes()
    }

    pub fn content_id(&self) -> ContentId {
        ContentId::hash(&self.canonical_bytes())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProviderGenesisDecodeError> {
        let mut decoder = Decoder::new(bytes);
        decoder.array(3, "provider enrollment bundle")?;
        decoder.tag("hellas.provider.enrollment.bundle.v1")?;
        let bundle = Self {
            genesis: decode_signed(&mut decoder)?,
            platform: decode_platform_enrollment(&mut decoder)?,
        };
        decoder.finish()?;
        if bundle.canonical_bytes() != bytes {
            return Err(ProviderGenesisDecodeError::new(
                "provider enrollment bundle is not canonical DAG-CBOR",
            ));
        }
        Ok(bundle)
    }
}

fn encode_statement(e: &mut DagCborEncoder, s: &ProviderGenesisStatement) {
    e.array(7);
    e.str("hellas.provider.genesis.statement.v2");
    e.u64(s.root_kind as u64);
    encode_public_key(e, &s.root_public_key);
    encode_public_key(e, &s.producer_public_key);
    encode_public_key(e, &s.transport_public_key);
    match s.platform_credential {
        PlatformCredential::Absent => {
            e.array(1);
            e.u64(0);
        }
        PlatformCredential::Registered(id) => {
            e.array(2);
            e.u64(1);
            e.bytes(id.as_bytes());
        }
    }
    e.bytes(&s.installation_nonce);
}

fn encode_signed(e: &mut DagCborEncoder, genesis: &SignedProviderGenesis) {
    e.array(3);
    e.str("hellas.provider.genesis.signed.v2");
    encode_statement(e, &genesis.statement);
    match &genesis.root_proof {
        RootProof::AppleAppAttest(proof) => encode_proof(e, 1, proof),
        RootProof::Software(signature) => {
            e.array(2);
            e.u64(3);
            encode_signature(e, signature);
        }
    }
}

fn encode_platform_enrollment(e: &mut DagCborEncoder, enrollment: &PlatformEnrollment) {
    match enrollment {
        PlatformEnrollment::Absent => {
            e.array(1);
            e.u64(0);
        }
        PlatformEnrollment::AppleAppAttest(enrollment) => {
            e.array(4);
            e.u64(1);
            e.bytes(&enrollment.attestation_object);
            e.bytes(&enrollment.client_data_hash);
            e.u64(enrollment.validation_time);
        }
    }
}

fn encode_proof(e: &mut DagCborEncoder, tag: u64, proof: &[u8]) {
    e.array(2);
    e.u64(tag);
    e.bytes(proof);
}

fn encode_public_key(e: &mut DagCborEncoder, key: &PublicKey) {
    e.array(2);
    e.u64(key.kind().to_byte() as u64);
    e.bytes(key.bytes());
}

fn encode_signature(e: &mut DagCborEncoder, signature: &Signature) {
    e.array(2);
    e.u64(signature.kind().to_byte() as u64);
    e.bytes(signature.bytes());
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid provider genesis: {message}")]
pub struct ProviderGenesisDecodeError {
    message: String,
}

impl ProviderGenesisDecodeError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

fn decode_signed(
    decoder: &mut Decoder<'_>,
) -> Result<SignedProviderGenesis, ProviderGenesisDecodeError> {
    decoder.array(3, "signed provider genesis")?;
    decoder.tag("hellas.provider.genesis.signed.v2")?;
    let statement = decode_statement(decoder)?;
    let root_proof = decode_proof(decoder)?;
    Ok(SignedProviderGenesis {
        statement,
        root_proof,
    })
}

fn decode_statement(
    decoder: &mut Decoder<'_>,
) -> Result<ProviderGenesisStatement, ProviderGenesisDecodeError> {
    decoder.array(7, "provider genesis statement")?;
    decoder.tag("hellas.provider.genesis.statement.v2")?;
    let root_kind = match decoder.u64("root kind")? {
        1 => RootKind::SecureEnclave,
        3 => RootKind::Software,
        value => {
            return Err(ProviderGenesisDecodeError::new(format!(
                "unknown root kind {value}"
            )));
        }
    };
    let root_public_key = decode_public_key(decoder)?;
    let producer_public_key = decode_public_key(decoder)?;
    let transport_public_key = decode_public_key(decoder)?;
    let platform_credential = decode_platform_credential(decoder)?;
    let installation_nonce = decoder.fixed_bytes("installation nonce")?;
    Ok(ProviderGenesisStatement {
        root_kind,
        root_public_key,
        producer_public_key,
        transport_public_key,
        platform_credential,
        installation_nonce,
    })
}

fn decode_platform_credential(
    decoder: &mut Decoder<'_>,
) -> Result<PlatformCredential, ProviderGenesisDecodeError> {
    let len = decoder.array_len("platform credential")?;
    let tag = decoder.u64("platform credential tag")?;
    match (tag, len) {
        (0, 1) => Ok(PlatformCredential::Absent),
        (1, 2) => Ok(PlatformCredential::Registered(ContentId::from_bytes(
            decoder.fixed_bytes("platform credential ContentId")?,
        ))),
        _ => Err(ProviderGenesisDecodeError::new(
            "invalid platform credential variant",
        )),
    }
}

fn decode_proof(decoder: &mut Decoder<'_>) -> Result<RootProof, ProviderGenesisDecodeError> {
    decoder.array(2, "provider genesis proof")?;
    match decoder.u64("provider genesis proof tag")? {
        1 => Ok(RootProof::AppleAppAttest(
            decoder.bytes("Apple App Attest proof")?.to_vec(),
        )),
        3 => Ok(RootProof::Software(decode_signature(decoder)?)),
        value => Err(ProviderGenesisDecodeError::new(format!(
            "unknown provider genesis proof tag {value}"
        ))),
    }
}

fn decode_platform_enrollment(
    decoder: &mut Decoder<'_>,
) -> Result<PlatformEnrollment, ProviderGenesisDecodeError> {
    let len = decoder.array_len("platform enrollment")?;
    match (decoder.u64("platform enrollment tag")?, len) {
        (0, 1) => Ok(PlatformEnrollment::Absent),
        (1, 4) => Ok(PlatformEnrollment::AppleAppAttest(
            AppleAppAttestEnrollment {
                attestation_object: decoder
                    .bytes("Apple App Attest attestation object")?
                    .to_vec(),
                client_data_hash: decoder.fixed_bytes("Apple App Attest client data hash")?,
                validation_time: decoder.u64("Apple App Attest validation time")?,
            },
        )),
        _ => Err(ProviderGenesisDecodeError::new(
            "invalid platform enrollment variant",
        )),
    }
}

fn decode_public_key(decoder: &mut Decoder<'_>) -> Result<PublicKey, ProviderGenesisDecodeError> {
    decoder.array(2, "public key")?;
    let kind = decode_signature_kind(decoder.u64("public key kind")?)?;
    let bytes = decoder.bytes("public key bytes")?;
    match kind {
        SignatureKind::Secp256k1 => fixed(bytes, "secp256k1 public key").map(PublicKey::Secp256k1),
        SignatureKind::Ed25519 => fixed(bytes, "Ed25519 public key").map(PublicKey::Ed25519),
        SignatureKind::P256 => fixed(bytes, "P-256 public key").map(PublicKey::P256),
    }
}

fn decode_signature(decoder: &mut Decoder<'_>) -> Result<Signature, ProviderGenesisDecodeError> {
    decoder.array(2, "signature")?;
    let kind = decode_signature_kind(decoder.u64("signature kind")?)?;
    let bytes = fixed(decoder.bytes("signature bytes")?, "signature")?;
    Ok(match kind {
        SignatureKind::Secp256k1 => Signature::Secp256k1(bytes),
        SignatureKind::Ed25519 => Signature::Ed25519(bytes),
        SignatureKind::P256 => Signature::P256(bytes),
    })
}

fn decode_signature_kind(value: u64) -> Result<SignatureKind, ProviderGenesisDecodeError> {
    let byte = u8::try_from(value)
        .map_err(|_| ProviderGenesisDecodeError::new("signature kind does not fit in one byte"))?;
    SignatureKind::from_byte(byte)
        .map_err(|error| ProviderGenesisDecodeError::new(error.to_string()))
}

fn fixed<const N: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; N], ProviderGenesisDecodeError> {
    bytes.try_into().map_err(|_| {
        ProviderGenesisDecodeError::new(format!("{field} must be {N} bytes, got {}", bytes.len()))
    })
}

/// Minimal DAG-CBOR decoder for protocol blobs whose canonical byte layout is
/// checked by decoding, finishing, and comparing the re-encoded bytes.
pub struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub fn finish(self) -> Result<(), ProviderGenesisDecodeError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ProviderGenesisDecodeError::new("trailing bytes"))
        }
    }

    pub fn array(
        &mut self,
        expected: u64,
        field: &'static str,
    ) -> Result<(), ProviderGenesisDecodeError> {
        let actual = self.array_len(field)?;
        if actual == expected {
            Ok(())
        } else {
            Err(ProviderGenesisDecodeError::new(format!(
                "{field} must contain {expected} items, got {actual}"
            )))
        }
    }

    pub fn array_len(&mut self, field: &'static str) -> Result<u64, ProviderGenesisDecodeError> {
        self.value(4, field)
    }

    pub fn tag(&mut self, expected: &'static str) -> Result<(), ProviderGenesisDecodeError> {
        let actual = self.text("domain tag")?;
        if actual == expected {
            Ok(())
        } else {
            Err(ProviderGenesisDecodeError::new(format!(
                "unexpected domain tag {actual:?}"
            )))
        }
    }

    pub fn u64(&mut self, field: &'static str) -> Result<u64, ProviderGenesisDecodeError> {
        self.value(0, field)
    }

    pub fn fixed_bytes<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], ProviderGenesisDecodeError> {
        fixed(self.bytes(field)?, field)
    }

    pub fn bytes(&mut self, field: &'static str) -> Result<&'a [u8], ProviderGenesisDecodeError> {
        let len = self.value(2, field)?;
        self.take(
            usize::try_from(len)
                .map_err(|_| ProviderGenesisDecodeError::new(format!("{field} is too large")))?,
            field,
        )
    }

    pub fn text(&mut self, field: &'static str) -> Result<&'a str, ProviderGenesisDecodeError> {
        let len = self.value(3, field)?;
        let bytes = self.take(
            usize::try_from(len)
                .map_err(|_| ProviderGenesisDecodeError::new(format!("{field} is too large")))?,
            field,
        )?;
        std::str::from_utf8(bytes)
            .map_err(|_| ProviderGenesisDecodeError::new(format!("{field} is not UTF-8")))
    }

    fn value(
        &mut self,
        expected_major: u8,
        field: &'static str,
    ) -> Result<u64, ProviderGenesisDecodeError> {
        let initial = *self
            .take(1, field)?
            .first()
            .expect("take(1) returns one byte");
        let major = initial >> 5;
        if major != expected_major {
            return Err(ProviderGenesisDecodeError::new(format!(
                "{field} has DAG-CBOR major type {major}, expected {expected_major}"
            )));
        }
        match initial & 0x1f {
            value @ 0..=23 => Ok(u64::from(value)),
            24 => Ok(u64::from(self.take(1, field)?[0])),
            25 => Ok(u64::from(u16::from_be_bytes(
                self.take(2, field)?.try_into().expect("two bytes"),
            ))),
            26 => Ok(u64::from(u32::from_be_bytes(
                self.take(4, field)?.try_into().expect("four bytes"),
            ))),
            27 => Ok(u64::from_be_bytes(
                self.take(8, field)?.try_into().expect("eight bytes"),
            )),
            _ => Err(ProviderGenesisDecodeError::new(format!(
                "{field} uses an unsupported indefinite or reserved encoding"
            ))),
        }
    }

    fn take(
        &mut self,
        len: usize,
        field: &'static str,
    ) -> Result<&'a [u8], ProviderGenesisDecodeError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| ProviderGenesisDecodeError::new(format!("{field} length overflow")))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| ProviderGenesisDecodeError::new(format!("truncated {field}")))?;
        self.offset = end;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Digest, ProducerSigningKey};

    fn genesis() -> SignedProviderGenesis {
        let root = ProducerSigningKey::from_secret_bytes([1; 32]).unwrap();
        let producer = ProducerSigningKey::from_secret_bytes([2; 32]).unwrap();
        let statement = ProviderGenesisStatement {
            root_kind: RootKind::Software,
            root_public_key: root.public_key(),
            producer_public_key: producer.public_key(),
            transport_public_key: PublicKey::Ed25519([3; 32]),
            platform_credential: PlatformCredential::Absent,
            installation_nonce: [4; 32],
        };
        SignedProviderGenesis {
            root_proof: RootProof::Software(
                root.sign_digest(Digest::hash(&statement.canonical_bytes()))
                    .unwrap(),
            ),
            statement,
        }
    }

    #[test]
    fn enrollment_bundle_canonical_decode_contract() {
        let bundle = ProviderEnrollmentBundle {
            genesis: genesis(),
            platform: PlatformEnrollment::AppleAppAttest(AppleAppAttestEnrollment {
                attestation_object: vec![5, 6, 7],
                client_data_hash: [8; 32],
                validation_time: 1_784_384_387,
            }),
        };
        let bytes = bundle.canonical_bytes();
        assert_eq!(
            ProviderEnrollmentBundle::from_canonical_bytes(&bytes).unwrap(),
            bundle
        );

        assert_eq!(bytes[0], 0x83);
        let mut noncanonical = vec![0x98, 0x03];
        noncanonical.extend_from_slice(&bytes[1..]);
        assert!(ProviderEnrollmentBundle::from_canonical_bytes(&noncanonical).is_err());

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ProviderEnrollmentBundle::from_canonical_bytes(&trailing).is_err());

        let nonce = [4; 32];
        let nonce_start = bytes
            .windows(34)
            .position(|window| window[..2] == [0x58, 0x20] && window[2..] == nonce)
            .unwrap();
        let mut wrong_length = bytes;
        wrong_length[nonce_start + 1] = 31;
        wrong_length.remove(nonce_start + 33);
        assert!(ProviderEnrollmentBundle::from_canonical_bytes(&wrong_length).is_err());
    }
}
