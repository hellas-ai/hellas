use std::collections::BTreeMap;

use hellas_rpc::{ContentId, pb::content as pb};
use prost::Message;

use super::{Error, Locator, Result};

const MAX_WIRE_BYTES: usize = 8 * 1024;
const MAX_OBJECTS: usize = 16;
const MAX_SOURCES: usize = 3;
const MAX_LOCATOR_BYTES: usize = 512;

/// Unsigned candidates for objects named by an authenticated work closure.
#[derive(Clone, Debug, Default)]
pub struct SourceHints(BTreeMap<ContentId, Vec<Locator>>);

impl SourceHints {
    pub fn new(entries: BTreeMap<ContentId, Vec<Locator>>) -> Result<Self> {
        if entries.values().any(Vec::is_empty) {
            return Err(Error::Invalid("empty source hints"));
        }
        let hints = Self(entries);
        let message = hints.message();
        check_entries(&message)?;
        if message.encoded_len() > MAX_WIRE_BYTES {
            return Err(Error::Invalid("source hints exceed 8 KiB"));
        }
        Ok(hints)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(Error::Invalid("source hints exceed 8 KiB"));
        }
        let message =
            pb::SourceHints::decode(bytes).map_err(|_| Error::Invalid("invalid source hints"))?;
        check_entries(&message)?;
        let mut entries = BTreeMap::new();
        for entry in message.entries {
            let id = entry
                .id
                .try_into()
                .map(ContentId::from_bytes)
                .map_err(|_| Error::Invalid("source hint content ID"))?;
            // A locator that cannot be interpreted is not an acquisition candidate.
            let sources = entry
                .locator
                .iter()
                .filter_map(|source| source.parse().ok())
                .collect();
            if entries.insert(id, sources).is_some() {
                return Err(Error::Invalid("duplicate source hint content ID"));
            }
        }
        Ok(Self(entries))
    }

    pub fn encode(&self) -> Vec<u8> {
        self.message().encode_to_vec()
    }

    pub fn sources(&self, id: ContentId) -> &[Locator] {
        self.0.get(&id).map(Vec::as_slice).unwrap_or_default()
    }

    fn message(&self) -> pb::SourceHints {
        pb::SourceHints {
            entries: self
                .0
                .iter()
                .filter(|(_, sources)| !sources.is_empty())
                .map(|(id, sources)| pb::SourceHint {
                    id: id.as_bytes().to_vec(),
                    locator: sources.iter().map(ToString::to_string).collect(),
                })
                .collect(),
        }
    }
}

fn check_entries(message: &pb::SourceHints) -> Result<()> {
    if message.entries.len() > MAX_OBJECTS
        || message.entries.iter().any(|entry| {
            entry.locator.is_empty()
                || entry.locator.len() > MAX_SOURCES
                || entry
                    .locator
                    .iter()
                    .any(|source| source.len() > MAX_LOCATOR_BYTES)
        })
    {
        return Err(Error::Invalid("source hint limits"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wire_decoder_bounds_total_bytes_ids_locators_and_lengths() {
        let entry = |byte, count, locator: &str| pb::SourceHint {
            id: vec![byte; 32],
            locator: vec![locator.into(); count],
        };
        let decode = |entries| SourceHints::decode(&pb::SourceHints { entries }.encode_to_vec());
        let url = "https://example.test/file";
        assert!(decode(vec![entry(0, 3, url)]).is_ok());
        assert!(decode(vec![entry(0, 4, url)]).is_err());
        assert!(decode(vec![entry(0, 1, &"x".repeat(513))]).is_err());
        assert!(decode((0..17).map(|id| entry(id, 1, url)).collect()).is_err());
        assert!(decode(vec![entry(0, 1, url), entry(0, 1, url)]).is_err());
        assert!(SourceHints::decode(&[0; MAX_WIRE_BYTES + 1]).is_err());

        let hints = decode(vec![entry(0, 1, "not a locator")]).unwrap();
        assert!(hints.sources(ContentId::from_bytes([0; 32])).is_empty());
    }
}
