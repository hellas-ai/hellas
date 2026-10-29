//! Bounded GGUF v3 tensor ranges for the F32/BF16 weights used by Catena models.
use std::{
    collections::BTreeSet,
    io::{self, Read, Seek, SeekFrom},
};

const MAX_HEADER_BYTES: u64 = 64 << 20;
const MAX_TENSORS: u64 = 65_536;
const MAX_METADATA: u64 = 1_000_000;
const MAX_ARRAY: u64 = 1_000_000;
const MAX_STRING: u64 = 1 << 20;
const MAX_NESTING: u8 = 8;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("GGUF I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("unsupported GGUF version {0}; expected version 3")]
    Version(u32),
    #[error("unsupported GGUF tensor type {0}; expected F32 or BF16")]
    Dtype(u32),
    #[error("invalid GGUF header: {0}")]
    Invalid(&'static str),
    #[error("GGUF {field} exceeds {limit}")]
    Limit { field: &'static str, limit: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dtype {
    F32,
    Bf16,
}
impl Dtype {
    fn bytes(self) -> u64 {
        match self {
            Self::F32 => 4,
            Self::Bf16 => 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tensor {
    pub name: String,
    pub dtype: Dtype,
    /// Logical shape, reversing GGUF's innermost-dimension-first order.
    pub shape: Vec<u64>,
    /// Absolute byte offset from the beginning of this GGUF file.
    pub offset: u64,
    pub bytes: u64,
}

#[derive(Debug)]
pub struct Header {
    pub data_offset: u64,
    pub tensors: Vec<Tensor>,
}

/// Reads the header from file offset zero, leaving the reader at tensor data.
/// Tensor data is not read; every returned range is checked against file length.
pub fn read_header<R: Read + Seek>(input: &mut R) -> Result<Header, Error> {
    let file_bytes = input.seek(SeekFrom::End(0))?;
    input.seek(SeekFrom::Start(0))?;
    let mut reader = HeaderReader {
        input,
        position: 0,
        file_bytes,
    };
    if reader.read::<4>()? != *b"GGUF" {
        return Err(Error::Invalid("magic"));
    }
    let version = reader.u32()?;
    if version != 3 {
        return Err(Error::Version(version));
    }
    let tensor_count = bounded(reader.u64()?, MAX_TENSORS, "tensor count")?;
    let metadata_count = bounded(reader.u64()?, MAX_METADATA, "metadata count")?;
    let mut alignment = 32;
    let mut aligned = false;
    for _ in 0..metadata_count {
        let key = reader.string(65_535, "metadata key")?;
        if key.is_empty() || !key.is_ascii() {
            return Err(Error::Invalid("metadata key"));
        }
        let kind = reader.u32()?;
        if key == "general.alignment" {
            if aligned {
                return Err(Error::Invalid("duplicate alignment"));
            }
            aligned = true;
            alignment = match kind {
                0 => u64::from(reader.read::<1>()?[0]),
                2 => u64::from(u16::from_le_bytes(reader.read()?)),
                4 => u64::from(reader.u32()?),
                10 => reader.u64()?,
                _ => return Err(Error::Invalid("alignment is not unsigned")),
            };
        } else {
            reader.skip_value(kind, 0)?;
        }
    }
    if alignment < 8 || !alignment.is_power_of_two() {
        return Err(Error::Invalid(
            "alignment must be a power of two of at least eight",
        ));
    }
    // Grow only for entries actually read, never from an untrusted count.
    let mut tensors = Vec::new();
    for _ in 0..tensor_count {
        let name = reader.string(64, "tensor name")?;
        if name.is_empty() {
            return Err(Error::Invalid("empty tensor name"));
        }
        let dimensions = bounded(u64::from(reader.u32()?), 4, "tensor rank")?;
        let mut shape = Vec::new();
        let mut elements = 1_u64;
        for _ in 0..dimensions {
            let dimension = reader.u64()?;
            if dimension == 0 {
                return Err(Error::Invalid("zero tensor dimension"));
            }
            elements = elements
                .checked_mul(dimension)
                .ok_or(Error::Invalid("tensor size overflow"))?;
            shape.push(dimension);
        }
        shape.reverse();
        let dtype = match reader.u32()? {
            0 => Dtype::F32,
            30 => Dtype::Bf16,
            other => return Err(Error::Dtype(other)),
        };
        let bytes = elements
            .checked_mul(dtype.bytes())
            .ok_or(Error::Invalid("tensor size overflow"))?;
        let offset = reader.u64()?;
        if !offset.is_multiple_of(alignment) {
            return Err(Error::Invalid("unaligned tensor offset"));
        }
        tensors.push(Tensor {
            name,
            dtype,
            shape,
            offset,
            bytes,
        });
    }
    let data_offset = reader
        .position
        .checked_add(alignment - 1)
        .map(|position| position & !(alignment - 1))
        .ok_or(Error::Invalid("data offset overflow"))?;
    if data_offset > file_bytes {
        return Err(Error::Invalid("tensor data starts past end of file"));
    }
    let mut names = BTreeSet::new();
    let mut ranges = Vec::new();
    for tensor in &mut tensors {
        if !names.insert(tensor.name.as_str()) {
            return Err(Error::Invalid("duplicate tensor name"));
        }
        tensor.offset = data_offset
            .checked_add(tensor.offset)
            .ok_or(Error::Invalid("tensor offset overflow"))?;
        let end = tensor
            .offset
            .checked_add(tensor.bytes)
            .ok_or(Error::Invalid("tensor range overflow"))?;
        if end > file_bytes {
            return Err(Error::Invalid("tensor range exceeds file"));
        }
        ranges.push((tensor.offset, end));
    }
    ranges.sort_unstable();
    if ranges
        .windows(2)
        .any(|pair| pair[0] != pair[1] && pair[1].0 < pair[0].1)
    {
        return Err(Error::Invalid("tensor ranges partially overlap"));
    }
    reader.input.seek(SeekFrom::Start(data_offset))?;
    Ok(Header {
        data_offset,
        tensors,
    })
}

fn bounded(value: u64, limit: u64, field: &'static str) -> Result<u64, Error> {
    if value > limit {
        Err(Error::Limit { field, limit })
    } else {
        Ok(value)
    }
}

struct HeaderReader<'a, R> {
    input: &'a mut R,
    position: u64,
    file_bytes: u64,
}
impl<R: Read + Seek> HeaderReader<'_, R> {
    fn advance(&mut self, bytes: u64) -> Result<(), Error> {
        let end = self
            .position
            .checked_add(bytes)
            .ok_or(Error::Invalid("header offset overflow"))?;
        bounded(end, MAX_HEADER_BYTES, "header bytes")?;
        if end > self.file_bytes {
            return Err(Error::Invalid("truncated header"));
        }
        self.position = end;
        Ok(())
    }
    fn read<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.advance(N as u64)?;
        let mut bytes = [0; N];
        self.input.read_exact(&mut bytes)?;
        Ok(bytes)
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.read()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.read()?))
    }
    fn string(&mut self, limit: u64, field: &'static str) -> Result<String, Error> {
        let bytes = bounded(self.u64()?, limit, field)?;
        self.advance(bytes)?;
        let mut value = vec![0; bytes as usize];
        self.input.read_exact(&mut value)?;
        String::from_utf8(value).map_err(|_| Error::Invalid("string is not UTF-8"))
    }
    fn skip(&mut self, bytes: u64) -> Result<(), Error> {
        self.advance(bytes)?;
        self.input.seek(SeekFrom::Start(self.position))?;
        Ok(())
    }
    fn skip_value(&mut self, kind: u32, depth: u8) -> Result<(), Error> {
        match kind {
            0 | 1 | 7 => self.skip(1),
            2 | 3 => self.skip(2),
            4..=6 => self.skip(4),
            10..=12 => self.skip(8),
            8 => self.string(MAX_STRING, "metadata string").map(|_| ()),
            9 => {
                bounded(
                    u64::from(depth),
                    u64::from(MAX_NESTING - 1),
                    "metadata nesting",
                )?;
                let element = self.u32()?;
                let count = bounded(self.u64()?, MAX_ARRAY, "metadata array count")?;
                let width = match element {
                    0 | 1 | 7 => Some(1),
                    2 | 3 => Some(2),
                    4..=6 => Some(4),
                    10..=12 => Some(8),
                    8 | 9 => None,
                    _ => return Err(Error::Invalid("unknown metadata array type")),
                };
                if let Some(width) = width {
                    self.skip(count * width)
                } else {
                    for _ in 0..count {
                        self.skip_value(element, depth + 1)?;
                    }
                    Ok(())
                }
            }
            _ => Err(Error::Invalid("unknown metadata type")),
        }
    }
}

#[cfg(test)]
mod tests;
