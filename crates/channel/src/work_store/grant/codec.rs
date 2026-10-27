use crate::model::work::PrivateRecord;
use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

pub mod record {
    use super::*;
    pub fn serialize<T: PrivateRecord, S: Serializer>(value: &T, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&value.encode())
    }
    pub fn deserialize<'de, T: PrivateRecord, D: Deserializer<'de>>(d: D) -> Result<T, D::Error> {
        T::decode(&serde_bytes::ByteBuf::deserialize(d)?).map_err(D::Error::custom)
    }
}
