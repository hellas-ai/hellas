//! Canonical field adapters; journal records contain commitments, never bodies.
use crate::model::grant::records::check_grant_provider;
use crate::model::work::PrivateRecord;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
pub(super) mod optional_provider {
    use super::*;
    use hellas_rpc::ProviderEnrollmentBundle;
    pub fn serialize<S: Serializer>(
        value: &Option<ProviderEnrollmentBundle>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .as_ref()
            .map(|p| serde_bytes::ByteBuf::from(p.canonical_bytes()))
            .serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<ProviderEnrollmentBundle>, D::Error> {
        Option::<serde_bytes::ByteBuf>::deserialize(d)?
            .map(|bytes| {
                if bytes.len() > crate::model::grant::records::MAX_ENROLLMENT_BYTES {
                    return Err(D::Error::custom("provider enrollment is too large"));
                }
                let provider = ProviderEnrollmentBundle::from_canonical_bytes(&bytes)
                    .map_err(D::Error::custom)?;
                check_grant_provider(&provider).map_err(D::Error::custom)?;
                Ok(provider)
            })
            .transpose()
    }
}
pub(super) mod record {
    use super::*;
    pub fn serialize<T: PrivateRecord, S: Serializer>(value: &T, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&value.encode())
    }
    pub fn deserialize<'de, T: PrivateRecord, D: Deserializer<'de>>(d: D) -> Result<T, D::Error> {
        T::decode(&serde_bytes::ByteBuf::deserialize(d)?).map_err(D::Error::custom)
    }
}
pub(super) mod entries {
    use super::*;
    use std::collections::BTreeMap;
    pub fn serialize<K: Serialize + Ord, V: Serialize, S: Serializer>(
        value: &BTreeMap<K, V>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        value.iter().collect::<Vec<_>>().serialize(s)
    }
    pub fn deserialize<
        'de,
        K: Deserialize<'de> + Ord,
        V: Deserialize<'de>,
        D: Deserializer<'de>,
    >(
        d: D,
    ) -> Result<BTreeMap<K, V>, D::Error> {
        let entries = Vec::<(K, V)>::deserialize(d)?;
        if entries.windows(2).any(|p| p[0].0 >= p[1].0) {
            return Err(D::Error::custom("unordered or duplicate map entries"));
        }
        Ok(entries.into_iter().collect())
    }
}
