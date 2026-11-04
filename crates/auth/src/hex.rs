//! Fixed-width identifiers in byte order, independent of content-hash display order.

pub fn parse<const N: usize>(text: &str) -> Result<[u8; N], ::hex::FromHexError> {
    let mut bytes = [0; N];
    ::hex::decode_to_slice(text, &mut bytes)?;
    Ok(bytes)
}

/// Canonical identifiers used in journals and externally verified index records.
pub fn parse_lower<const N: usize>(text: &str) -> Result<[u8; N], ::hex::FromHexError> {
    let bytes = parse(text)?;
    if let Some((index, byte)) = text
        .bytes()
        .enumerate()
        .find(|(_, b)| b.is_ascii_uppercase())
    {
        return Err(::hex::FromHexError::InvalidHexCharacter {
            c: char::from(byte),
            index,
        });
    }
    Ok(bytes)
}

/// Serde for an identifier whose text form is its `Display`/`FromStr`:
/// human-readable formats carry that lowercase text; binary formats carry the
/// wrapped value exactly as a derived newtype would, keeping canonical bytes.
#[macro_export]
macro_rules! printable_identifier {
    ($ty:ty, $inner:ty) => {
        impl serde::Serialize for $ty {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                if serializer.is_human_readable() {
                    serializer.collect_str(self)
                } else {
                    serde::Serialize::serialize(&self.0, serializer)
                }
            }
        }
        impl<'de> serde::Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                if deserializer.is_human_readable() {
                    let text = <String as serde::Deserialize>::deserialize(deserializer)?;
                    if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
                        return Err(serde::de::Error::custom(
                            "identifiers are lowercase hexadecimal",
                        ));
                    }
                    text.parse().map_err(serde::de::Error::custom)
                } else {
                    <$inner as serde::Deserialize>::deserialize(deserializer).map(Self)
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{AuthorityId, CredentialId, GrantId, PrincipalId, ResourceId};

    #[test]
    fn identifiers_preserve_byte_order_and_their_text_rules() {
        let text = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let bytes: [u8; 32] = std::array::from_fn(|i| i as u8);
        let authority: AuthorityId = text.parse().unwrap();
        let resource: ResourceId = text.parse().unwrap();
        assert_eq!(authority.0.as_bytes(), &bytes);
        assert_eq!(resource.0.as_bytes(), &bytes);
        assert_eq!(authority.to_string(), text);
        assert_eq!(AuthorityId::try_from(bytes.as_slice()).unwrap(), authority);
        assert_eq!(resource.to_string(), text);
        let grant: GrantId = text[..32].parse().unwrap();
        let credential: CredentialId = text[..32].parse().unwrap();
        assert_eq!(grant.0, bytes[..16]);
        assert_eq!(credential.0, grant.0);
        assert_eq!(grant.to_string(), &text[..32]);
        assert_eq!(credential.to_string(), &text[..32]);
        assert_eq!(parse::<32>(&text.to_uppercase()).unwrap(), bytes);
        assert!(parse_lower::<32>(&text.to_uppercase()).is_err());
        for invalid in ["", "+0", "0", "00 ", "é", "gg"] {
            assert!(parse::<1>(invalid).is_err());
        }
        assert!(GrantId::try_from(bytes.as_slice()).is_err());
        assert!(PrincipalId::try_from([0; 33].as_slice()).is_err());
    }

    #[test]
    fn operator_files_print_identifiers_and_cbor_keeps_their_bytes() {
        use crate::authority::NodeKey;
        use crate::test_support::actors::FRIEND;
        let bytes: [u8; 32] = std::array::from_fn(|i| i as u8);
        let digest = crate::Digest::from_bytes(bytes);
        let resource = ResourceId(digest);
        let authority = AuthorityId(digest);
        let grant = GrantId(std::array::from_fn(|i| i as u8));
        let credential = CredentialId(grant.0);
        let principal = FRIEND.principal();
        let node = NodeKey::from_public_key(FRIEND.node_key().public_key()).unwrap();

        // Each identifier's JSON form is its Display text, which parses back.
        assert_eq!(json(&resource), format!("\"{resource}\""));
        assert_eq!(json(&authority), format!("\"{authority}\""));
        assert_eq!(json(&grant), format!("\"{grant}\""));
        assert_eq!(json(&credential), format!("\"{credential}\""));
        assert_eq!(json(&digest), format!("\"{digest}\""));
        assert_eq!(json(&principal), format!("\"{principal}\""));
        assert!(principal.to_string().starts_with("p256:"));
        assert!(json(&node).starts_with("\"secp256k1:"));
        assert_eq!(
            principal.to_string().parse::<PrincipalId>().unwrap(),
            principal
        );
        assert_eq!(
            serde_json::from_str::<ResourceId>(&json(&resource)).unwrap(),
            resource
        );
        assert_eq!(
            serde_json::from_str::<GrantId>(&json(&grant)).unwrap(),
            grant
        );
        assert_eq!(
            serde_json::from_str::<crate::Digest>(&json(&digest)).unwrap(),
            digest
        );
        assert_eq!(
            serde_json::from_str::<PrincipalId>(&json(&principal)).unwrap(),
            principal
        );
        assert_eq!(serde_json::from_str::<NodeKey>(&json(&node)).unwrap(), node);

        // Byte arrays, uppercase and wrong widths are refused in operator files.
        let array = serde_json::to_string(&grant.0).unwrap();
        assert!(serde_json::from_str::<GrantId>(&array).is_err());
        assert!(
            serde_json::from_str::<ResourceId>(&serde_json::to_string(&bytes).unwrap()).is_err()
        );
        assert!(
            serde_json::from_str::<crate::Digest>(&serde_json::to_string(&bytes).unwrap()).is_err()
        );
        assert!(serde_json::from_str::<GrantId>(&json(&grant).to_uppercase()).is_err());
        assert!(serde_json::from_str::<crate::Digest>(&json(&digest).to_uppercase()).is_err());
        assert!(serde_json::from_str::<GrantId>("\"00\"").is_err());
        assert!(
            serde_json::from_str::<PrincipalId>(&json(&principal).replace("p256:", "")).is_err()
        );
        assert!(
            serde_json::from_str::<PrincipalId>(&json(&principal).replace("p256:", "ed25519:"))
                .is_err()
        );

        // DAG-CBOR keeps exactly the encodings the derived impls produced.
        assert_eq!(cbor(&grant), serde_ipld_dagcbor::to_vec(&grant.0).unwrap());
        assert_eq!(
            cbor(&credential),
            serde_ipld_dagcbor::to_vec(&grant.0).unwrap()
        );
        assert_eq!(
            cbor(&resource),
            serde_ipld_dagcbor::to_vec(&serde_bytes::Bytes::new(&bytes)).unwrap()
        );
        assert_eq!(cbor(&authority), cbor(&digest));
        assert_eq!(
            cbor(&principal),
            serde_ipld_dagcbor::to_vec(&(
                principal.public_key().kind(),
                serde_bytes::Bytes::new(principal.public_key().bytes())
            ))
            .unwrap()
        );
        assert_eq!(
            serde_ipld_dagcbor::from_slice::<GrantId>(&cbor(&grant)).unwrap(),
            grant
        );
        assert_eq!(
            serde_ipld_dagcbor::from_slice::<ResourceId>(&cbor(&resource)).unwrap(),
            resource
        );
        assert_eq!(
            serde_ipld_dagcbor::from_slice::<PrincipalId>(&cbor(&principal)).unwrap(),
            principal
        );
        assert!(
            serde_ipld_dagcbor::from_slice::<crate::Digest>(
                &serde_ipld_dagcbor::to_vec(&digest.to_string()).unwrap()
            )
            .is_err()
        );
    }

    fn json<T: serde::Serialize>(value: &T) -> String {
        serde_json::to_string(value).unwrap()
    }
    fn cbor<T: serde::Serialize>(value: &T) -> Vec<u8> {
        serde_ipld_dagcbor::to_vec(value).unwrap()
    }
}
