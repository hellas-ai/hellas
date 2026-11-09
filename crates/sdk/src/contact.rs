//! The one string a person sends to be shared with: their signed contact card
//! and the node key of the device the shared credential will be bound to.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use base64::Engine as _;
use hellas_auth::authority::{ContactCard, NodeKey};
use hellas_authority::model::grant::records::MAX_CONTACT_CARD_BYTES;
use hellas_rpc::protocol::value::{canonical_dag_cbor, decode_canonical_bounded};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "hellas-contact:";
const TAG: &str = "hellas.contact.v1";

pub struct Contact {
    /// The principal and display name, signed by the principal's key.
    pub card: ContactCard,
    /// The device that will hold a credential shared with this contact.
    pub holder: NodeKey,
}

#[derive(Debug, thiserror::Error)]
#[error("not a hellas contact")]
pub struct ContactError;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    tag: String,
    card: ContactCard,
    holder: NodeKey,
}

impl Contact {
    /// `hellas-contact:` followed by base64url canonical DAG-CBOR.
    pub fn encode(&self) -> Result<String, ContactError> {
        let bytes = canonical_dag_cbor(&Wire {
            tag: TAG.into(),
            card: self.card.clone(),
            holder: self.holder,
        })
        .map_err(|_| ContactError)?;
        Ok(format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        ))
    }

    /// Decoding verifies the card's signature by its principal.
    pub fn decode(text: &str) -> Result<Self, ContactError> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text.trim().strip_prefix(PREFIX).ok_or(ContactError)?)
            .map_err(|_| ContactError)?;
        let wire: Wire = decode_canonical_bounded(&bytes, MAX_CONTACT_CARD_BYTES + 256)
            .map_err(|_| ContactError)?;
        if wire.tag != TAG {
            return Err(ContactError);
        }
        Ok(Self {
            card: wire.card,
            holder: wire.holder,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_authority::authenticator::Authenticator as _;

    #[tokio::test]
    async fn a_contact_round_trips_and_a_forged_card_does_not_decode() {
        let passkey = hellas_kernel::SoftPasskey::from_secret_scalar([0x41; 32]).unwrap();
        let principal = hellas_auth::authority::PrincipalId::from_public_key(
            hellas_auth::PublicKey::P256(passkey.public_key().unwrap().to_compressed()),
        )
        .unwrap();
        let assertion = passkey
            .assert(ContactCard::digest(principal, "friend"))
            .await
            .unwrap();
        let card = ContactCard::new(principal, "friend".into(), assertion).unwrap();
        let holder =
            NodeKey::from_public_key(hellas_auth::ProducerSigningKey::generate().public_key())
                .unwrap();
        let line = Contact { card, holder }.encode().unwrap();
        assert!(line.starts_with(PREFIX) && !line.contains(char::is_whitespace));
        let decoded = Contact::decode(&format!("{line}\n")).unwrap();
        assert_eq!(decoded.card.principal(), principal);
        assert_eq!(decoded.card.name(), "friend");
        assert_eq!(decoded.holder, holder);
        // The same card claiming another name no longer verifies.
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut bytes = engine.decode(&line[PREFIX.len()..]).unwrap();
        let at = bytes.windows(6).position(|w| w == b"friend").unwrap();
        bytes[at] = b'F';
        assert!(Contact::decode(&format!("{PREFIX}{}", engine.encode(bytes))).is_err());
        assert!(Contact::decode(&line[PREFIX.len()..]).is_err());
    }
}
