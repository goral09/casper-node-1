use std::{collections::HashMap, marker::PhantomData};

use casper_types::PublicKey;
use datasize::DataSize;
use itertools::Itertools;
use tracing::{debug, warn};

use super::SignatureCache;
use crate::{
    components::consensus::EraId,
    types::{Block, BlockHash, BlockSignatures, FinalitySignature},
};

/// The maximum number of finality signatures from a single validator we keep in memory while
/// waiting for their block.
const MAX_PENDING_FINALITY_SIGNATURES_PER_VALIDATOR: usize = 1000;

#[derive(DataSize, Debug)]
pub(crate) struct LinearChainState<I> {
    /// The most recently added block.
    pub(crate) latest_block: Option<Block>,
    /// Finality signatures to be inserted in a block once it is available.
    pending_finality_signatures: HashMap<PublicKey, HashMap<BlockHash, FinalitySignature>>,
    pub(crate) signature_cache: SignatureCache,
    _marker: PhantomData<I>,
}

#[derive(Default)]
pub(crate) struct NewFinalitySignatures(Vec<FinalitySignature>);

impl NewFinalitySignatures {
    pub(crate) fn add(&mut self, fs: FinalitySignature) {
        self.0.push(fs);
    }
}

impl IntoIterator for NewFinalitySignatures {
    type Item = FinalitySignature;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<I> LinearChainState<I> {
    pub(crate) fn new() -> Self {
        LinearChainState {
            latest_block: None,
            pending_finality_signatures: HashMap::new(),
            signature_cache: SignatureCache::new(),
            _marker: PhantomData,
        }
    }

    pub(crate) fn latest_block(&self) -> &Option<Block> {
        &self.latest_block
    }

    // Checks if we have already enqueued that finality signature.
    pub(crate) fn has_finality_signature(&self, fs: &FinalitySignature) -> bool {
        let creator = fs.public_key;
        let block_hash = fs.block_hash;
        self.pending_finality_signatures
            .get(&creator)
            .map_or(false, |sigs| sigs.contains_key(&block_hash))
    }

    /// Removes all entries for which there are no finality signatures.
    pub(crate) fn remove_empty_entries(&mut self) {
        self.pending_finality_signatures
            .retain(|_, sigs| !sigs.is_empty());
    }

    /// Adds pending finality signatures to the block; returns events to announce and broadcast
    /// them, and the updated block.
    pub(crate) fn collect_pending_finality_signatures(
        &mut self,
        block_hash: &BlockHash,
        block_era: EraId,
    ) -> (BlockSignatures, NewFinalitySignatures) {
        let mut known_signatures = self
            .signature_cache
            .get_known_signatures(block_hash, block_era);
        let new_signatures = self
            .pending_finality_signatures
            .values_mut()
            .filter_map(|sigs| sigs.remove(&block_hash).map(Box::new))
            .filter(|fs| !known_signatures.proofs.contains_key(&fs.public_key))
            .collect_vec();
        self.remove_empty_entries();
        let mut new_fs = NewFinalitySignatures::default();
        // Add new signatures and send the updated block to storage.
        for fs in new_signatures {
            if fs.era_id != block_era {
                // finality signature was created with era id that doesn't match block's era.
                // TODO: disconnect from the sender.
                continue;
            }
            if known_signatures.proofs.contains_key(&fs.public_key) {
                // Don't send finality signatures we already know of.
                continue;
            }
            known_signatures.insert_proof(fs.public_key, fs.signature);
            new_fs.add(*fs);
        }
        (known_signatures, new_fs)
    }

    /// Adds finality signature to the collection of pending finality signatures.
    pub(crate) fn add_pending_finality_signature(&mut self, fs: FinalitySignature) {
        let FinalitySignature {
            block_hash,
            public_key,
            ..
        } = fs;
        debug!(%block_hash, %public_key, "received new finality signature");
        let sigs = self
            .pending_finality_signatures
            .entry(public_key)
            .or_default();
        // Limit the memory we use for storing unknown signatures from each validator.
        if sigs.len() >= MAX_PENDING_FINALITY_SIGNATURES_PER_VALIDATOR {
            warn!(
                %block_hash, %public_key,
                "received too many finality signatures for unknown blocks"
            );
            return;
        }
        // Add the pending signature.
        let _ = sigs.insert(block_hash, fs);
    }

    /// Removes finality signature from the pending collection.
    pub(crate) fn remove_from_pending_fs(&mut self, fs: &FinalitySignature) {
        let FinalitySignature {
            block_hash,
            era_id: _era_id,
            signature: _signature,
            public_key,
        } = fs;
        debug!(%block_hash, %public_key, "removing finality signature from pending collection");
        if let Some(validator_sigs) = self.pending_finality_signatures.get_mut(public_key) {
            validator_sigs.remove(&block_hash);
        }
        self.remove_empty_entries();
    }
}
