//! A Simplex finalization certifies its block and every hash-linked ancestor.
//!
//! Direct certificates retain their existing wire encoding. An ancestor proof carries
//! each canonical child block through a directly certified descendant. Full blocks are
//! necessary because Hellas hashes the complete encoding, rather than a separate header.
use crate::{
    ConsensusVerificationError as Error, ConsensusVerifier, Finalization, HellasBlock, LatestBlock,
};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{Block as _, CertifiableBlock as _, Heightable as _};
use commonware_cryptography::Digestible as _;

// Ten continuation bytes cannot begin a valid legacy u64 epoch varint.
const MAGIC: &[u8] = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xffHLSF\x01";
pub const MAX_FINALITY_PROOF_BYTES: usize = 3 * 1024 * 1024;
pub const MAX_FINALITY_DESCENDANTS: usize = 256;
const MAX_CERTIFICATE_BYTES: usize = 4096;

pub struct FinalityProof {
    pub certificate: Finalization,
    pub descendants: Vec<HellasBlock>,
}

impl FinalityProof {
    pub fn decode(encoded: &[u8]) -> Result<Self, Error> {
        if encoded.len() > MAX_FINALITY_PROOF_BYTES {
            return Err(Error::InvalidFinalization);
        }
        let Some(mut reader) = encoded.strip_prefix(MAGIC) else {
            if encoded.len() > MAX_CERTIFICATE_BYTES {
                return Err(Error::InvalidFinalization);
            }
            return Ok(Self {
                certificate: ConsensusVerifier::decode_finalization(encoded)?,
                descendants: Vec::new(),
            });
        };
        let certificate_bytes = take_bytes(&mut reader)?;
        if certificate_bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(Error::InvalidFinalization);
        }
        let certificate = ConsensusVerifier::decode_finalization(certificate_bytes)?;
        let count = take_u32(&mut reader)? as usize;
        if !(1..=MAX_FINALITY_DESCENDANTS).contains(&count) {
            return Err(Error::InvalidFinalization);
        }
        let mut descendants = Vec::with_capacity(count);
        for _ in 0..count {
            let bytes = take_bytes(&mut reader)?;
            let block = HellasBlock::decode(bytes).map_err(|_| Error::InvalidFinalization)?;
            if block.encode().as_ref() != bytes {
                return Err(Error::InvalidFinalization);
            }
            descendants.push(block);
        }
        if !reader.is_empty() {
            return Err(Error::InvalidFinalization);
        }
        Ok(Self {
            certificate,
            descendants,
        })
    }

    /// Structural checks precede signature verification and any native archive mutation.
    pub fn verify(
        &self,
        verifier: &ConsensusVerifier,
        snapshot: &LatestBlock,
    ) -> Result<(), Error> {
        let mut payload = snapshot.payload;
        let mut height = snapshot.height;
        for child in &self.descendants {
            height = height.checked_add(1).ok_or(Error::InvalidFinalization)?;
            if child.height().get() != height || child.parent() != payload {
                return Err(Error::PayloadMismatch);
            }
            payload = child.digest();
        }
        if let Some(terminal) = self.descendants.last() {
            self.verify_terminal_context(terminal)?;
        }
        verifier.verify_finalization(&self.certificate, payload)
    }

    /// The target block must be checked too when the proof is a direct certificate.
    pub fn verify_terminal_context(&self, terminal: &HellasBlock) -> Result<(), Error> {
        let context = terminal.context();
        #[cfg(any(feature = "indexer", feature = "validator"))]
        let matches = context.round == self.certificate.proposal.round
            && context.parent.0 == self.certificate.proposal.parent;
        #[cfg(not(any(feature = "indexer", feature = "validator")))]
        let matches = context.round.epoch().get() == self.certificate.proposal.round.epoch
            && context.round.view().get() == self.certificate.proposal.round.view
            && context.parent.0.get() == self.certificate.proposal.parent;
        if !matches {
            return Err(Error::InvalidFinalization);
        }
        Ok(())
    }

    pub fn certified_height(&self, target_height: u64) -> Result<u64, Error> {
        target_height
            .checked_add(self.descendants.len() as u64)
            .ok_or(Error::InvalidFinalization)
    }

    pub fn certificate_epoch(&self) -> u64 {
        #[cfg(any(feature = "indexer", feature = "validator"))]
        {
            self.certificate.proposal.round.epoch().get()
        }
        #[cfg(not(any(feature = "indexer", feature = "validator")))]
        {
            self.certificate.proposal.round.epoch
        }
    }
}

#[cfg(any(feature = "indexer", feature = "validator", test))]
pub(crate) fn encode(certificate: &[u8], descendants: &[HellasBlock]) -> Result<Vec<u8>, Error> {
    if descendants.is_empty() {
        return Ok(certificate.to_vec());
    }
    if descendants.len() > MAX_FINALITY_DESCENDANTS {
        return Err(Error::InvalidFinalization);
    }
    let mut bytes = MAGIC.to_vec();
    append_bytes(&mut bytes, certificate)?;
    bytes.extend_from_slice(&(descendants.len() as u32).to_be_bytes());
    for block in descendants {
        append_bytes(&mut bytes, &block.encode())?;
    }
    Ok(bytes)
}

#[cfg(any(feature = "indexer", feature = "validator", test))]
fn append_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    if out.len().saturating_add(4).saturating_add(bytes.len()) > MAX_FINALITY_PROOF_BYTES {
        return Err(Error::InvalidFinalization);
    }
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn take_u32(reader: &mut &[u8]) -> Result<u32, Error> {
    let (bytes, tail) = reader
        .split_at_checked(4)
        .ok_or(Error::InvalidFinalization)?;
    *reader = tail;
    Ok(u32::from_be_bytes(bytes.try_into().expect("four bytes")))
}

fn take_bytes<'a>(reader: &mut &'a [u8]) -> Result<&'a [u8], Error> {
    let len = take_u32(reader)? as usize;
    let (bytes, tail) = reader
        .split_at_checked(len)
        .ok_or(Error::InvalidFinalization)?;
    *reader = tail;
    Ok(bytes)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
