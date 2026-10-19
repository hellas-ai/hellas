//! Deterministic helpers and fixtures for the kernel WebAuthn v1 wire format.
//!
//! Everything in this module is gated by the crate's `test-support` feature.
//! It is suitable for integration tests and examples.

use hellas_webauthn::{
    AUTHENTICATOR_DATA_LEN, FLAG_AT as AT, FLAG_ED as ED, FLAG_UP as UP, encode_challenge,
};

use super::WebAuthnError;
use super::soft_passkey::{
    SOFT_PASSKEY_ORIGIN, SOFT_PASSKEY_RP_ID_HASH, SoftPasskey, SoftPasskeyError, append,
    sign_assertion_data,
};
use crate::{
    Auth, CloseKind, CoinId, EdgeId, Funding, Key, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS,
    MAX_WEBAUTHN_DATA_LENGTH, NetworkId, Parties, PayloadHash, Payout, Proof, ProtocolCode, Terms,
    Tx, WebAuthnAssertion, consts::P256_COORDINATE_LENGTH, context::BlockHeight,
};

/// Number of named invalid fixtures returned by [`negative_assertions`].
pub const WEBAUTHN_NEGATIVE_FIXTURE_COUNT: usize = 9;

/// The network every fixture in this module is bound to.
///
/// Fixture authorizations commit to it, so a consumer that executes
/// [`valid_open_tx`] or [`valid_mutual_close_tx`] must build its
/// [`crate::Context`] with this exact network — under any other one the
/// signature is correctly rejected.
pub const FIXTURE_NETWORK: NetworkId = match NetworkId::new("hellas-fixture-1") {
    Some(network) => network,
    None => panic!("literal is a legal network id"),
};

/// Named valid `WebAuthn` v1 fixture.
#[derive(Debug, Clone)]
pub struct WebAuthnFixture {
    name: &'static str,
    assertion: WebAuthnAssertion,
    party_key: Key,
    payload_hash: PayloadHash,
}

impl WebAuthnFixture {
    /// Returns the stable vector name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the assertion under test.
    #[must_use]
    pub const fn assertion(&self) -> &WebAuthnAssertion {
        &self.assertion
    }

    /// Returns the expected compressed SEC1 signer key.
    #[must_use]
    pub const fn party_key(&self) -> Key {
        self.party_key
    }

    /// Returns the canonical payload hash embedded as the challenge.
    #[must_use]
    pub const fn payload_hash(&self) -> PayloadHash {
        self.payload_hash
    }
}

/// Named invalid `WebAuthn` v1 fixture with its pinned verifier error.
#[derive(Debug, Clone)]
pub struct InvalidWebAuthnFixture {
    name: &'static str,
    assertion: WebAuthnAssertion,
    party_key: Key,
    payload_hash: PayloadHash,
    expected_error: WebAuthnError,
}

impl InvalidWebAuthnFixture {
    /// Returns the stable vector name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the assertion under test.
    #[must_use]
    pub const fn assertion(&self) -> &WebAuthnAssertion {
        &self.assertion
    }

    /// Returns the party key supplied to the verifier.
    #[must_use]
    pub const fn party_key(&self) -> Key {
        self.party_key
    }

    /// Returns the payload hash supplied to the verifier.
    #[must_use]
    pub const fn payload_hash(&self) -> PayloadHash {
        self.payload_hash
    }

    /// Returns the exact verifier error this vector must produce.
    #[must_use]
    pub const fn expected_error(&self) -> WebAuthnError {
        self.expected_error
    }
}

/// Builds the named valid assertion over [`Tx::open_hash`].
///
/// # Errors
///
/// Returns [`SoftPasskeyError`] if the deterministic fixture cannot be built.
pub fn valid_open_assertion() -> Result<WebAuthnFixture, SoftPasskeyError> {
    let context = fixture_context()?;
    let assertion = context.passkey.sign(context.open_hash)?;
    Ok(WebAuthnFixture {
        name: "valid_open_assertion",
        assertion,
        party_key: context.passkey.party_key(),
        payload_hash: context.open_hash,
    })
}

/// Builds the named valid assertion over a mutual-close [`Tx::payload_hash`].
///
/// # Errors
///
/// Returns [`SoftPasskeyError`] if the deterministic fixture cannot be built.
pub fn valid_mutual_close_assertion() -> Result<WebAuthnFixture, SoftPasskeyError> {
    let context = fixture_context()?;
    let assertion = context.passkey.sign(context.mutual_close_hash)?;
    Ok(WebAuthnFixture {
        name: "valid_mutual_close_assertion",
        assertion,
        party_key: context.passkey.party_key(),
        payload_hash: context.mutual_close_hash,
    })
}

/// Builds a complete valid kernel open transaction using deterministic
/// software-passkey authorizations for both parties.
///
/// # Errors
///
/// Returns [`SoftPasskeyError`] if deterministic signing or bounded fixture
/// assembly fails.
pub fn valid_open_tx() -> Result<Tx, SoftPasskeyError> {
    let context = fixture_context()?;
    let maker_auth = Auth::webauthn(context.passkey.sign(context.open_hash)?);
    let taker_auth = Auth::webauthn(context.other.sign(context.open_hash)?);
    Ok(Tx::open(
        context.funding,
        context.terms,
        maker_auth,
        taker_auth,
    ))
}

/// Builds a complete valid kernel mutual-close transaction using
/// deterministic software-passkey authorizations for both parties.
///
/// # Errors
///
/// Returns [`SoftPasskeyError`] if deterministic signing or bounded fixture
/// assembly fails.
pub fn valid_mutual_close_tx() -> Result<Tx, SoftPasskeyError> {
    let context = fixture_context()?;
    let maker_auth = Auth::webauthn(context.passkey.sign(context.mutual_close_hash)?);
    let taker_auth = Auth::webauthn(context.other.sign(context.mutual_close_hash)?);
    Ok(Tx::close(
        context.edge,
        Proof::mutual(maker_auth, taker_auth),
        context.outputs,
    ))
}

/// Builds all named invalid v1 assertions and their exact expected errors.
///
/// # Errors
///
/// Returns [`SoftPasskeyError`] if deterministic signing or bounded fixture
/// assembly fails.
#[allow(
    clippy::large_stack_arrays,
    reason = "the no-alloc fixture API returns one compile-time bounded array"
)]
pub fn negative_assertions()
-> Result<[InvalidWebAuthnFixture; WEBAUTHN_NEGATIVE_FIXTURE_COUNT], SoftPasskeyError> {
    let context = fixture_context()?;
    let wrong_challenge = PayloadHash::from_bytes([0x5a; PayloadHash::LENGTH]);
    let wrong_signer = SoftPasskey::from_secret_scalar([9; P256_COORDINATE_LENGTH])?;
    let party_key = context.passkey.party_key();
    let hash = context.open_hash;

    Ok([
        invalid_fixture(
            "wrong_challenge",
            build_assertion(
                &context.passkey,
                wrong_challenge,
                UP,
                ClientDataKind::Valid,
                false,
            )?,
            party_key,
            hash,
            WebAuthnError::InvalidChallenge,
        ),
        invalid_fixture(
            "high_s",
            build_assertion(&context.passkey, hash, UP, ClientDataKind::Valid, true)?,
            party_key,
            hash,
            WebAuthnError::HighS,
        ),
        invalid_fixture(
            "wrong_signer_key",
            wrong_signer.sign(hash)?,
            party_key,
            hash,
            WebAuthnError::SignerMismatch,
        ),
        invalid_fixture(
            "attested_credential_data",
            build_assertion(
                &context.passkey,
                hash,
                UP | AT,
                ClientDataKind::Valid,
                false,
            )?,
            party_key,
            hash,
            WebAuthnError::AttestedCredentialDataUnsupported,
        ),
        invalid_fixture(
            "extension_data",
            build_assertion(
                &context.passkey,
                hash,
                UP | ED,
                ClientDataKind::Valid,
                false,
            )?,
            party_key,
            hash,
            WebAuthnError::ExtensionsUnsupported,
        ),
        invalid_fixture(
            "missing_user_presence_and_verification",
            build_assertion(&context.passkey, hash, 0, ClientDataKind::Valid, false)?,
            party_key,
            hash,
            WebAuthnError::MissingUserPresence,
        ),
        invalid_fixture(
            "nested_json_injection",
            build_assertion(
                &context.passkey,
                hash,
                UP,
                ClientDataKind::NestedInjection,
                false,
            )?,
            party_key,
            hash,
            WebAuthnError::InvalidClientDataJson,
        ),
        invalid_fixture(
            "duplicate_required_field",
            build_assertion(
                &context.passkey,
                hash,
                UP,
                ClientDataKind::DuplicateChallenge,
                false,
            )?,
            party_key,
            hash,
            WebAuthnError::DuplicateClientDataField,
        ),
        invalid_fixture(
            "wrong_client_data_type",
            build_assertion(&context.passkey, hash, UP, ClientDataKind::WrongType, false)?,
            party_key,
            hash,
            WebAuthnError::InvalidClientDataType,
        ),
    ])
}

const fn invalid_fixture(
    name: &'static str,
    assertion: WebAuthnAssertion,
    party_key: Key,
    payload_hash: PayloadHash,
    expected_error: WebAuthnError,
) -> InvalidWebAuthnFixture {
    InvalidWebAuthnFixture {
        name,
        assertion,
        party_key,
        payload_hash,
        expected_error,
    }
}

struct FixtureContext {
    passkey: SoftPasskey,
    other: SoftPasskey,
    funding: Funding,
    terms: Terms,
    outputs: List<Payout, MAX_EDGE_OUTPUTS>,
    edge: EdgeId,
    open_hash: PayloadHash,
    mutual_close_hash: PayloadHash,
}

fn fixture_context() -> Result<FixtureContext, SoftPasskeyError> {
    let passkey = SoftPasskey::from_secret_scalar([7; P256_COORDINATE_LENGTH])?;
    let other = SoftPasskey::from_secret_scalar([8; P256_COORDINATE_LENGTH])?;
    let maker = List::take(
        [CoinId::from_bytes([0x11; CoinId::LENGTH]); MAX_PARTY_INPUTS],
        1,
    );
    let taker = List::take(
        [CoinId::from_bytes([0x22; CoinId::LENGTH]); MAX_PARTY_INPUTS],
        1,
    );
    let funding = Funding::new(maker, taker);
    let mut payout_values = [Payout::default(); MAX_EDGE_OUTPUTS];
    if let Some(maker_payout) = payout_values.first_mut() {
        *maker_payout = Payout::new(passkey.party_key(), 40);
    }
    if let Some(taker_payout) = payout_values.get_mut(1) {
        *taker_payout = Payout::new(other.party_key(), 60);
    }
    let outputs = List::take(payout_values, 2);
    let terms = Terms::basic(
        ProtocolCode::new(1),
        Parties::new(passkey.party_key(), other.party_key()),
        BlockHeight::new(100),
        outputs.clone(),
    );
    let open_hash = Tx::open_hash(FIXTURE_NETWORK, &funding, &terms);
    let edge = Tx::edge_id_of(&funding, &terms);
    let mutual_close_hash = Tx::payload_hash(
        FIXTURE_NETWORK,
        edge,
        CloseKind::Mutual,
        terms.hash(),
        &outputs,
    );

    Ok(FixtureContext {
        passkey,
        other,
        funding,
        terms,
        outputs,
        edge,
        open_hash,
        mutual_close_hash,
    })
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ClientDataKind {
    Valid,
    NestedInjection,
    DuplicateChallenge,
    WrongType,
}

fn build_assertion(
    passkey: &SoftPasskey,
    challenge_hash: PayloadHash,
    flags: u8,
    client_data_kind: ClientDataKind,
    force_high_s: bool,
) -> Result<WebAuthnAssertion, SoftPasskeyError> {
    let mut data = [0_u8; MAX_WEBAUTHN_DATA_LENGTH];
    let mut len = 0;
    append(&mut data, &mut len, &SOFT_PASSKEY_RP_ID_HASH)?;
    append(&mut data, &mut len, &[flags])?;
    append(&mut data, &mut len, &[0; 4])?;
    if len != AUTHENTICATOR_DATA_LEN {
        return Err(SoftPasskeyError::AssertionTooLarge);
    }

    write_client_data(&mut data, &mut len, challenge_hash, client_data_kind)?;
    let assertion = sign_assertion_data(passkey, data, len)?;
    if force_high_s {
        return Ok(WebAuthnAssertion::new(
            *assertion.r(),
            [0xff; P256_COORDINATE_LENGTH],
            *assertion.pub_key_x(),
            *assertion.pub_key_y(),
            assertion.webauthn_data().clone(),
        ));
    }
    Ok(assertion)
}

fn write_client_data(
    data: &mut [u8; MAX_WEBAUTHN_DATA_LENGTH],
    len: &mut usize,
    challenge_hash: PayloadHash,
    kind: ClientDataKind,
) -> Result<(), SoftPasskeyError> {
    append(data, len, b"{\"type\":\"")?;
    match kind {
        ClientDataKind::WrongType => append(data, len, b"webauthn.create")?,
        _ => append(data, len, b"webauthn.get")?,
    }
    append(data, len, b"\",\"challenge\":\"")?;
    let challenge = encode_challenge(challenge_hash.as_bytes());
    append(data, len, &challenge)?;
    append(data, len, b"\"")?;
    append(data, len, b",\"origin\":\"")?;
    append(data, len, SOFT_PASSKEY_ORIGIN)?;
    append(data, len, b"\",\"crossOrigin\":false")?;

    match kind {
        ClientDataKind::DuplicateChallenge => {
            append(data, len, b",\"challenge\":\"")?;
            append(data, len, &challenge)?;
            append(data, len, b"\"")?;
        }
        ClientDataKind::NestedInjection => {
            append(data, len, b",\"extra\":{\"challenge\":\"")?;
            append(data, len, &challenge)?;
            append(data, len, b"\"}")?;
        }
        ClientDataKind::Valid | ClientDataKind::WrongType => {}
    }

    append(data, len, b"}")
}
