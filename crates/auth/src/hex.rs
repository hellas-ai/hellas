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
}
