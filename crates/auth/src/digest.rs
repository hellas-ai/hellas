use crate::tags;
pub use hellas_xet::XetHash as Digest;

pub fn hash_tuple(tag: &str, fields: &[&[u8]]) -> Digest {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(tags::HASH_TUPLE_V2.as_bytes());
    bytes.extend_from_slice(&(tag.len() as u32).to_be_bytes());
    bytes.extend_from_slice(tag.as_bytes());
    bytes.extend_from_slice(&(fields.len() as u32).to_be_bytes());
    for field in fields {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    Digest::hash(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tuple_boundaries_and_domains_are_distinct() {
        assert_ne!(
            hash_tuple("tag", &[b"ab", b"c"]),
            hash_tuple("tag", &[b"a", b"bc"])
        );
        assert_ne!(hash_tuple("tag", &[b"abc"]), hash_tuple("other", &[b"abc"]));
    }
}
