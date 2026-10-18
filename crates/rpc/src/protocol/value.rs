use serde::Serialize;
use serde::de::DeserializeOwned;
use std::str;

pub type DagCborEncodeError = serde_ipld_dagcbor::EncodeError<std::collections::TryReserveError>;
pub type DagCborDecodeError = serde_ipld_dagcbor::DecodeError<std::convert::Infallible>;

pub fn all_distinct<T: Ord>(values: impl IntoIterator<Item = T>) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    values.into_iter().all(|value| seen.insert(value))
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, serde::Deserialize)]
pub struct JsonBytes(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl JsonBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Requested heap capacity retained by the owned JSON buffer.
    #[must_use]
    pub fn retained_heap_bytes(&self) -> usize {
        self.0.capacity()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

pub fn canonical_dag_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, DagCborEncodeError> {
    serde_ipld_dagcbor::to_vec(value)
}

pub fn decode_dag_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DagCborDecodeError> {
    serde_ipld_dagcbor::from_slice(bytes)
}

#[derive(Debug, thiserror::Error)]
pub enum BoundedCborError {
    #[error("DAG-CBOR input exceeds its limit")]
    InputLimit,
    #[error("encoded DAG-CBOR exceeds its limit")]
    OutputLimit,
    #[error(transparent)]
    Invalid(#[from] CanonicalDecodeError),
}

pub fn encode_bounded<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, BoundedCborError> {
    let bytes = canonical_dag_cbor(value).map_err(|error| {
        CanonicalDecodeError::new(format!("could not canonicalize decoded DAG-CBOR: {error}"))
    })?;
    if bytes.len() > maximum {
        return Err(BoundedCborError::OutputLimit);
    }
    Ok(bytes)
}

/// Bound the input before invoking its deserializer, including for noncanonical protocols.
pub fn decode_bounded<T: DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, BoundedCborError> {
    if bytes.len() > maximum {
        return Err(BoundedCborError::InputLimit);
    }
    decode_dag_cbor(bytes)
        .map_err(|error| CanonicalDecodeError::new(format!("invalid DAG-CBOR: {error}")).into())
}

pub fn decode_canonical_bounded<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, BoundedCborError> {
    let value = decode_bounded(bytes, maximum)?;
    if encode_bounded(&value, maximum)? != bytes {
        return Err(CanonicalDecodeError::new("DAG-CBOR body is not canonically encoded").into());
    }
    Ok(value)
}

/// Decode a value only when `bytes` are its one canonical DAG-CBOR spelling.
///
/// `serde_ipld_dagcbor` accepts some semantically equivalent CBOR encodings on
/// input. That is useful at an ordinary serialization boundary, but not for a
/// signed protocol body whose canonicalization identifier promises exact
/// bytes. Decode and re-encode before exposing the value so a verifier cannot
/// accept a spelling that another implementation rejects.
pub fn decode_canonical_dag_cbor<T>(bytes: &[u8]) -> Result<T, CanonicalDecodeError>
where
    T: DeserializeOwned + Serialize,
{
    decode_canonical_bounded(bytes, usize::MAX).map_err(|error| match error {
        BoundedCborError::Invalid(error) => error,
        error => CanonicalDecodeError::new(error.to_string()),
    })
}

/// Minimal strict DAG-CBOR encoder for commitment blobs whose byte layout is
/// part of the protocol. Use this when serde's struct/enum representation would
/// obscure the exact canonical preimage.
pub struct DagCborEncoder {
    bytes: Vec<u8>,
}

impl DagCborEncoder {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn array(&mut self, len: u64) {
        self.header(4, len);
    }

    pub fn bytes(&mut self, value: &[u8]) {
        self.header(2, value.len() as u64);
        self.bytes.extend_from_slice(value);
    }

    pub fn str(&mut self, value: &str) {
        self.header(3, value.len() as u64);
        self.bytes.extend_from_slice(value.as_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.header(0, value);
    }

    pub fn i64(&mut self, value: i64) {
        if value >= 0 {
            self.header(0, value as u64);
        } else {
            self.header(1, (-1_i128 - value as i128) as u64);
        }
    }

    fn header(&mut self, major: u8, value: u64) {
        let major = major << 5;
        match value {
            0..=23 => self.bytes.push(major | value as u8),
            24..=0xff => self.bytes.extend_from_slice(&[major | 24, value as u8]),
            0x100..=0xffff => {
                self.bytes.push(major | 25);
                self.bytes.extend_from_slice(&(value as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.bytes.push(major | 26);
                self.bytes.extend_from_slice(&(value as u32).to_be_bytes());
            }
            _ => {
                self.bytes.push(major | 27);
                self.bytes.extend_from_slice(&value.to_be_bytes());
            }
        }
    }
}

impl Default for DagCborEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Why a canonical body was refused.
///
/// One message-carrying type rather than a variant per field: these
/// errors are read by humans debugging a mismatched artifact, and every
/// caller treats them the same way — the body is not the body it claimed
/// to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalDecodeError {
    message: String,
}

impl CanonicalDecodeError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl core::fmt::Display for CanonicalDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.message.fmt(f)
    }
}

impl core::error::Error for CanonicalDecodeError {}

/// Strict reader for the canonical DAG-CBOR bodies [`DagCborEncoder`]
/// writes.
///
/// Strict in the three ways a content-addressed body needs: it rejects a
/// noncanonical integer width, it rejects an indefinite length, and
/// [`Self::finish`] rejects trailing bytes. A caller that also re-encodes
/// what it decoded and compares therefore has exactly one legal spelling
/// per value, which is what makes the hash of these bytes an identifier
/// rather than one of several.
pub struct CanonicalDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CanonicalDecoder<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub fn finish(&self) -> Result<(), CanonicalDecodeError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CanonicalDecodeError::new(format!(
                "trailing bytes after canonical object: {}",
                self.bytes.len() - self.offset
            )))
        }
    }

    pub fn array_exact(&mut self, expected: u64) -> Result<(), CanonicalDecodeError> {
        let actual = self.read_len(4)?;
        if actual == expected {
            Ok(())
        } else {
            Err(CanonicalDecodeError::new(format!(
                "expected array length {expected}, got {actual}"
            )))
        }
    }

    pub fn array_len(&mut self) -> Result<usize, CanonicalDecodeError> {
        let len = usize::try_from(self.read_len(4)?)
            .map_err(|_| CanonicalDecodeError::new("array length exceeds usize range"))?;
        let remaining = self.bytes.len().saturating_sub(self.offset);
        // Every definite-length CBOR array element occupies at least one
        // byte. Reject impossible lengths before callers reserve a vector;
        // otherwise a tiny hostile artifact can trigger a capacity panic or
        // an enormous allocation before decoding reaches EOF.
        if len > remaining {
            return Err(CanonicalDecodeError::new(format!(
                "array declares {len} elements but only {remaining} encoded bytes remain"
            )));
        }
        Ok(len)
    }

    pub fn bytes_32(&mut self) -> Result<[u8; 32], CanonicalDecodeError> {
        let bytes = self.bytes()?;
        bytes.try_into().map_err(|_| {
            CanonicalDecodeError::new(format!("expected 32 bytes, got {}", bytes.len()))
        })
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], CanonicalDecodeError> {
        let len = usize::try_from(self.read_len(2)?)
            .map_err(|_| CanonicalDecodeError::new("byte string length exceeds usize range"))?;
        self.read_exact(len)
    }

    pub fn expect_str(&mut self, expected: &str) -> Result<(), CanonicalDecodeError> {
        let actual = self.str()?;
        if actual == expected {
            Ok(())
        } else {
            Err(CanonicalDecodeError::new(format!(
                "expected schema tag {expected:?}, got {actual:?}"
            )))
        }
    }

    pub fn str(&mut self) -> Result<&'a str, CanonicalDecodeError> {
        let len = usize::try_from(self.read_len(3)?)
            .map_err(|_| CanonicalDecodeError::new("text string length exceeds usize range"))?;
        let bytes = self.read_exact(len)?;
        str::from_utf8(bytes)
            .map_err(|err| CanonicalDecodeError::new(format!("invalid utf-8: {err}")))
    }

    pub fn u32(&mut self) -> Result<u32, CanonicalDecodeError> {
        u32::try_from(self.u64()?)
            .map_err(|_| CanonicalDecodeError::new("integer exceeds u32 range"))
    }

    pub fn u64(&mut self) -> Result<u64, CanonicalDecodeError> {
        self.read_len(0)
    }

    fn read_len(&mut self, expected_major: u8) -> Result<u64, CanonicalDecodeError> {
        let first = self.read_u8()?;
        let major = first >> 5;
        if major != expected_major {
            return Err(CanonicalDecodeError::new(format!(
                "expected CBOR major type {expected_major}, got {major}"
            )));
        }
        let additional = first & 0x1f;
        match additional {
            0..=23 => Ok(additional as u64),
            24 => {
                let value = self.read_u8()? as u64;
                if value < 24 {
                    return Err(CanonicalDecodeError::new("non-canonical one-byte integer"));
                }
                Ok(value)
            }
            25 => {
                let value = u16::from_be_bytes(self.read_array()?);
                if value <= 0xff {
                    return Err(CanonicalDecodeError::new("non-canonical two-byte integer"));
                }
                Ok(value as u64)
            }
            26 => {
                let value = u32::from_be_bytes(self.read_array()?);
                if value <= 0xffff {
                    return Err(CanonicalDecodeError::new("non-canonical four-byte integer"));
                }
                Ok(value as u64)
            }
            27 => {
                let value = u64::from_be_bytes(self.read_array()?);
                if value <= 0xffff_ffff {
                    return Err(CanonicalDecodeError::new(
                        "non-canonical eight-byte integer",
                    ));
                }
                Ok(value)
            }
            _ => Err(CanonicalDecodeError::new(
                "unsupported indefinite or reserved CBOR length",
            )),
        }
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], CanonicalDecodeError> {
        let bytes = self.read_exact(N)?;
        let mut array = [0u8; N];
        array.copy_from_slice(bytes);
        Ok(array)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], CanonicalDecodeError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| CanonicalDecodeError::new("decoder offset overflow"))?;
        if end > self.bytes.len() {
            return Err(CanonicalDecodeError::new("unexpected end of CBOR input"));
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn read_u8(&mut self) -> Result<u8, CanonicalDecodeError> {
        Ok(self.read_exact(1)?[0])
    }
}
