use hellas_rpc::{ContentId, ContentRef};
use hellas_wire::canonical::{Encode, Writer};

use super::{Error, Result, Target};

pub const MAX_NAME_BYTES: usize = 255;
pub const MAX_TREE_ENTRIES: usize = 10_000;
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_TREE_BYTES: usize = 4 + MAX_TREE_ENTRIES * (4 + MAX_NAME_BYTES + 1 + 32 + 8);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PinName(String);
impl PinName {
    pub fn new(name: String) -> Result<Self> {
        validate_path(&name, false)?;
        Ok(Self(name))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub(super) fn validate_path(path: &str, empty: bool) -> Result<()> {
    if path.len() > MAX_PATH_BYTES || (!empty && path.is_empty()) {
        return Err(Error::Invalid("path length"));
    }
    if !path.is_empty() {
        for name in path.split('/') {
            validate_name(name)?;
        }
    }
    Ok(())
}
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > MAX_NAME_BYTES
        || name.contains(['/', '\0'])
        || matches!(name, "." | "..")
    {
        return Err(Error::Invalid("tree name"));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tree {
    entries: Vec<(String, Target)>,
}
impl Tree {
    pub fn new(mut entries: Vec<(String, Target)>) -> Result<Self> {
        if entries.len() > MAX_TREE_ENTRIES {
            return Err(Error::Invalid("tree entries"));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (index, (name, _)) in entries.iter().enumerate() {
            validate_name(name)?;
            if index != 0 && entries[index - 1].0 == *name {
                return Err(Error::Invalid("duplicate tree name"));
            }
        }
        Ok(Self { entries })
    }
    pub fn entries(&self) -> &[(String, Target)] {
        &self.entries
    }
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_size());
        self.encode_to(&mut bytes);
        bytes
    }
    pub fn object(&self) -> ContentRef {
        ContentRef::for_bytes(&self.bytes())
    }
    pub fn decode(mut bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_TREE_BYTES {
            return Err(Error::Invalid("tree encoding length"));
        }
        let count = u32::from_be_bytes(take(&mut bytes, 4)?.try_into().unwrap()) as usize;
        if count > MAX_TREE_ENTRIES || count > bytes.len() / (4 + 1 + 1 + 32 + 8) {
            return Err(Error::Invalid("tree entry count"));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let len = u32::from_be_bytes(take(&mut bytes, 4)?.try_into().unwrap()) as usize;
            if len > MAX_NAME_BYTES {
                return Err(Error::Invalid("tree name length"));
            }
            let name = std::str::from_utf8(take(&mut bytes, len)?)
                .map_err(|_| Error::Invalid("tree UTF-8"))?
                .to_owned();
            validate_name(&name)?;
            if entries
                .last()
                .is_some_and(|(old, _): &(String, Target)| *old >= name)
            {
                return Err(Error::Invalid("unsorted tree"));
            }
            let tag = take(&mut bytes, 1)?[0];
            let id = ContentId::from_slice(take(&mut bytes, 32)?)
                .map_err(|_| Error::Invalid("content id"))?;
            let len = u64::from_be_bytes(take(&mut bytes, 8)?.try_into().unwrap());
            let object = ContentRef::new(id, len);
            let target = match tag {
                0 => Target::Object(object),
                1 => Target::Tree(object),
                _ => return Err(Error::Invalid("tree tag")),
            };
            entries.push((name, target));
        }
        if !bytes.is_empty() {
            return Err(Error::Invalid("trailing tree bytes"));
        }
        Ok(Self { entries })
    }
}
fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8]> {
    let Some((head, tail)) = bytes.split_at_checked(count) else {
        return Err(Error::Invalid("truncated tree"));
    };
    *bytes = tail;
    Ok(head)
}
impl Encode for Tree {
    const MAX_ENCODED_SIZE: usize = MAX_TREE_BYTES;
    fn encoded_size(&self) -> usize {
        4 + self
            .entries
            .iter()
            .map(|(name, _)| 4 + name.len() + 1 + 32 + 8)
            .sum::<usize>()
    }
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        (self.entries.len() as u32).encode_to(writer);
        for (name, target) in &self.entries {
            name.as_str().encode_to(writer);
            match target {
                Target::Object(_) => 0u8,
                Target::Tree(_) => 1u8,
            }
            .encode_to(writer);
            writer.write(target.object().id().as_bytes());
            target.object().bytes().encode_to(writer);
        }
    }
}
