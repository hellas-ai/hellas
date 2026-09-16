//! Reading one finalized block, and finding one transaction in it.
//!
//! # What a finalized block proves, and what it does not
//!
//! A [`crate::FinalizedBlock`] is a snapshot and a bag of bytes. The
//! snapshot's finalization certificate proves that a quorum finalized a
//! payload digest; it says nothing about the bytes beside it, and
//! nothing about what those bytes contain. [`FinalizedBlockView::decode`]
//! is the step that closes that gap: it hashes the bytes, compares them
//! with the payload the certificate named, decodes them exactly, and
//! checks the block's own height and state root against the snapshot's.
//!
//! Only then is "this transaction is in this block" a fact. An endpoint
//! that trusted the bytes because the snapshot beside them was signed
//! would accept any block from a peer willing to attach a real
//! certificate to it.
//!
//! # Why the codec is not copied
//!
//! The block a client decodes and the block a validator proposed have to
//! be the same object, so this reads [`crate::HellasBlock`] rather than a
//! second definition of it. A private endpoint decoder that agreed with
//! the validator's until one of them changed is how a client comes to
//! believe a transaction was accepted when it was not.

use crate::domain::{Digest, Transaction};
use crate::light_client::LatestBlock;
use crate::{FinalizedBlock, HellasBlock};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{Block as _, Heightable as _};
use commonware_cryptography::{Digestible as _, Hasher as _, Sha256};

/// Why a block's bytes are not the block a snapshot named.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlockViewError {
    /// The bytes are not a canonical block: truncated, over-long
    /// transaction count, bad field length, or trailing bytes.
    #[error("block bytes are not a canonical block")]
    Malformed,
    /// The bytes hash to a different payload than the finalization
    /// certificate names.
    #[error("block bytes hash to {actual}, not the finalized payload {expected}")]
    PayloadMismatch {
        /// Payload the snapshot's certificate covers.
        expected: Digest,
        /// Payload the bytes actually produce.
        actual: Digest,
    },
    /// The decoded block sits at a different height than the snapshot.
    #[error("block is at height {actual}, not the finalized height {expected}")]
    HeightMismatch {
        /// Height the snapshot names.
        expected: u64,
        /// Height the block carries.
        actual: u64,
    },
    /// The decoded block commits to a different state root than the
    /// snapshot.
    #[error("block commits to state root {actual}, not the snapshot's {expected}")]
    StateRootMismatch {
        /// Root the snapshot names.
        expected: Digest,
        /// Root the block carries.
        actual: Digest,
    },
}

/// One finalized block, checked against the snapshot that named it.
///
/// It can only be built by [`Self::decode`], so holding one is holding
/// the four checks that constructor makes.
#[derive(Debug, Clone)]
pub struct FinalizedBlockView {
    block: HellasBlock,
    snapshot: LatestBlock,
}

impl FinalizedBlockView {
    /// Decodes one finalized block and checks it is the block its
    /// snapshot names.
    ///
    /// Trailing bytes are refused by the payload check rather than by
    /// the decoder: the digest is taken over every byte handed in, so a
    /// canonical prefix followed by anything at all hashes to something
    /// the certificate does not name. The re-encoding check below closes
    /// the other direction, where bytes decode and encode back
    /// differently.
    ///
    /// This does not verify the finalization certificate. That is
    /// `ConsensusVerifier`'s, and the light client applies it while
    /// reading the snapshot. What is established here is the binding
    /// between a verified snapshot and these bytes.
    pub fn decode(finalized: &FinalizedBlock) -> Result<Self, BlockViewError> {
        let actual = Sha256::hash(&finalized.block);
        if actual != finalized.snapshot.payload {
            return Err(BlockViewError::PayloadMismatch {
                expected: finalized.snapshot.payload,
                actual,
            });
        }
        let block = HellasBlock::decode(finalized.block.as_slice())
            .map_err(|_| BlockViewError::Malformed)?;
        // The digest is over the block's own re-encoding, so a body
        // that decodes but re-encodes differently would pass the hash
        // check above and fail here. Nothing in the codec promises that
        // cannot happen; this is what makes the promise.
        if block.digest() != finalized.snapshot.payload {
            return Err(BlockViewError::Malformed);
        }
        let height = block.height().get();
        if height != finalized.snapshot.height {
            return Err(BlockViewError::HeightMismatch {
                expected: finalized.snapshot.height,
                actual: height,
            });
        }
        if block.state_root() != finalized.snapshot.state_root {
            return Err(BlockViewError::StateRootMismatch {
                expected: finalized.snapshot.state_root,
                actual: block.state_root(),
            });
        }
        Ok(Self {
            block,
            snapshot: finalized.snapshot.clone(),
        })
    }

    /// Owner commitment from the exact canonical block authenticated by its certificate.
    pub fn owner_root(&self) -> [u8; 32] {
        self.block.owner_root()
    }

    /// Returns the finalized height of this block.
    #[must_use]
    pub fn height(&self) -> u64 {
        self.snapshot.height
    }

    /// Returns this block's payload digest.
    #[must_use]
    pub const fn payload(&self) -> Digest {
        self.snapshot.payload
    }

    /// Returns the payload digest of this block's parent.
    ///
    /// A cursor is contiguous only if each block names the previous
    /// one; a scan that took blocks by height alone would accept a gap.
    #[must_use]
    pub fn parent(&self) -> Digest {
        self.block.parent()
    }

    /// Returns the state root this block commits to.
    #[must_use]
    pub const fn state_root(&self) -> Digest {
        self.snapshot.state_root
    }

    /// Returns the transactions this block accepted, in block order.
    #[must_use]
    pub fn txs(&self) -> &[Transaction] {
        self.block.txs()
    }

    /// Returns the position of a transaction whose canonical bytes are
    /// exactly `wanted`, or `None`.
    ///
    /// Compares encodings rather than values: what an endpoint retained
    /// and can resubmit is a byte string, and "a transaction equal to
    /// mine was accepted" is a weaker claim than "these bytes were".
    #[must_use]
    pub fn position_of(&self, wanted: &Transaction) -> Option<usize> {
        let wanted = wanted.encode();
        self.block.txs().iter().position(|tx| tx.encode() == wanted)
    }
}

#[cfg(all(test, feature = "validator"))]
mod tests {
    use super::*;
    use crate::execution::test_support::{index_block, index_genesis};
    use crate::light_client::LatestBlock;

    #[test]
    fn owner_layout_requires_the_new_canonical_block_format() {
        let block = index_genesis().with_owner_root([7; 32]);
        let bytes = block.encode();
        assert!(bytes.starts_with(b"HLS2"));
        let decoded = HellasBlock::decode(bytes.as_ref()).unwrap();
        assert_eq!(decoded.owner_root(), [7; 32]);
        assert!(HellasBlock::decode(&bytes[4..]).is_err());
    }

    fn finalized(block: &HellasBlock, state_root: Digest) -> FinalizedBlock {
        FinalizedBlock {
            snapshot: LatestBlock {
                height: block.height().get(),
                payload: block.digest(),
                state_root,
                finalization: vec![0x01],
            },
            block: block.encode().to_vec(),
        }
    }

    fn open_tx() -> Transaction {
        let Ok(tx) = hellas_kernel::test_support::valid_open_tx() else {
            panic!("the deterministic fixture signs");
        };
        Transaction::Kernel(tx)
    }

    fn close_tx() -> Transaction {
        let Ok(tx) = hellas_kernel::test_support::valid_mutual_close_tx() else {
            panic!("the deterministic fixture signs");
        };
        Transaction::Kernel(tx)
    }

    /// Every way the bytes can fail to be the block the snapshot named,
    /// each differing from the accepted case in exactly one thing.
    #[test]
    fn a_block_is_only_this_snapshots_block_when_all_four_checks_hold() {
        let state_root = Digest::from([0x0c; 32]);
        let genesis = index_genesis();
        let carried = open_tx();
        let block = index_block(&genesis, state_root, vec![carried.clone()]);
        let good = finalized(&block, state_root);

        let view = FinalizedBlockView::decode(&good).expect("its own snapshot names it");
        assert_eq!(view.height(), block.height().get());
        assert_eq!(view.payload(), block.digest());
        assert_eq!(view.parent(), genesis.digest());
        assert_eq!(view.state_root(), state_root);
        assert_eq!(view.txs().len(), 1);
        assert_eq!(view.position_of(&carried), Some(0));

        // A transaction the block does not carry.
        let uncarried = close_tx();
        assert_ne!(uncarried.encode(), carried.encode());
        assert_eq!(view.position_of(&uncarried), None);

        // One trailing byte. The bytes decode as a prefix and are not
        // the block that was finalized.
        let mut trailing = good.clone();
        trailing.block.push(0);
        assert!(matches!(
            FinalizedBlockView::decode(&trailing),
            Err(BlockViewError::PayloadMismatch { .. }),
        ));

        // The right payload beside another block's bytes.
        let other = index_block(&genesis, state_root, Vec::new());
        let mut swapped = good.clone();
        swapped.block = other.encode().to_vec();
        assert!(matches!(
            FinalizedBlockView::decode(&swapped),
            Err(BlockViewError::PayloadMismatch { .. }),
        ));

        // Bytes that are not a block at all.
        let mut garbage = good.clone();
        garbage.block = vec![0xff; 8];
        garbage.snapshot.payload = Sha256::hash(&garbage.block);
        assert_eq!(
            FinalizedBlockView::decode(&garbage).err(),
            Some(BlockViewError::Malformed),
        );

        // The block's own height and root, contradicted by the snapshot
        // that carries them. Only one field moves in each.
        let mut wrong_height = good.clone();
        wrong_height.snapshot.height = block.height().get() + 1;
        assert_eq!(
            FinalizedBlockView::decode(&wrong_height).err(),
            Some(BlockViewError::HeightMismatch {
                expected: block.height().get() + 1,
                actual: block.height().get(),
            }),
        );

        let mut wrong_root = good;
        wrong_root.snapshot.state_root = Digest::from([0x0d; 32]);
        assert_eq!(
            FinalizedBlockView::decode(&wrong_root).err(),
            Some(BlockViewError::StateRootMismatch {
                expected: Digest::from([0x0d; 32]),
                actual: state_root,
            }),
        );
    }

    /// The view decodes exactly what a validator encoded, transaction by
    /// transaction and byte for byte.
    #[test]
    fn accepted_transactions_match_the_validators_own_encoding() {
        let state_root = Digest::from([0x0e; 32]);
        let genesis = index_genesis();
        let txs = vec![open_tx(), close_tx()];
        let block = index_block(&genesis, state_root, txs.clone());

        let view = FinalizedBlockView::decode(&finalized(&block, state_root))
            .expect("its own snapshot names it");
        assert_eq!(view.txs().len(), txs.len());
        for (index, expected) in txs.iter().enumerate() {
            let Some(decoded) = view.txs().get(index) else {
                panic!("the block carries {} transactions", txs.len());
            };
            assert_eq!(decoded.encode(), expected.encode());
            assert_eq!(view.position_of(expected), Some(index));
        }
    }
}
