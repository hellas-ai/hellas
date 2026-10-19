//! A person's introduction of their principal to someone who will grant it.
//! The card proves possession of the passkey; it grants nothing by itself.
use super::*;
use crate::{Digest, hash_tuple};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

const TAG: &str = "hellas.contact-card.v1";
pub const MAX_CONTACT_NAME_BYTES: usize = 64;

/// A friend's passkey public key and display name, with their passkey's
/// assertion over both. Compare [`PrincipalId::fingerprint`] out of band.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactCard {
    principal: PrincipalId,
    name: String,
    assertion: PasskeyAssertion,
}

impl ContactCard {
    /// The challenge the principal's passkey signs. It commits to the tagged
    /// key and the exact display name.
    pub fn digest(principal: PrincipalId, name: &str) -> Digest {
        let key = principal.public_key();
        hash_tuple(
            TAG,
            &[&[key.kind().to_byte()], key.bytes(), name.as_bytes()],
        )
    }

    /// A card whose assertion verifies; anything else is refused.
    pub fn new(
        principal: PrincipalId,
        name: String,
        assertion: PasskeyAssertion,
    ) -> Result<Self, AuthorityError> {
        if name.is_empty()
            || name.len() > MAX_CONTACT_NAME_BYTES
            || name.chars().any(char::is_control)
        {
            return Err(AuthorityError::Invalid);
        }
        assertion.verify(principal, Self::digest(principal, &name))?;
        Ok(Self {
            principal,
            name,
            assertion,
        })
    }

    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }
    /// The name the principal chose for itself, for display only.
    pub fn name(&self) -> &str {
        &self.name
    }
    pub const fn assertion(&self) -> &PasskeyAssertion {
        &self.assertion
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    tag: String,
    principal: PrincipalId,
    name: String,
    assertion: PasskeyAssertion,
}

impl Serialize for ContactCard {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Wire {
            tag: TAG.into(),
            principal: self.principal,
            name: self.name.clone(),
            assertion: self.assertion.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ContactCard {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = Wire::deserialize(deserializer)?;
        if wire.tag != TAG {
            return Err(D::Error::custom("not a contact card"));
        }
        Self::new(wire.principal, wire.name, wire.assertion).map_err(D::Error::custom)
    }
}
