use std::collections::{hash_map::Entry, HashMap};

use crate::{
    components::consensus::EraId,
    types::{BlockHash, BlockSignatures, FinalitySignature},
};

use datasize::DataSize;

#[derive(DataSize, Debug)]
pub(crate) struct SignatureCache {
    curr_era: EraId,
    signatures: HashMap<BlockHash, BlockSignatures>,
}

impl SignatureCache {
    pub(crate) fn new() -> Self {
        SignatureCache {
            curr_era: EraId(0),
            signatures: Default::default(),
        }
    }

    pub(crate) fn get(&mut self, hash: &BlockHash, _era_id: EraId) -> Option<BlockSignatures> {
        self.signatures.get(hash).cloned()
    }

    pub(crate) fn insert(&mut self, block_signature: BlockSignatures) {
        // We optimistically assume that most of the signatures that arrive in close temporal
        // proximity refer to the same era.
        if self.curr_era < block_signature.era_id {
            self.signatures.clear();
            self.curr_era = block_signature.era_id;
        }
        match self.signatures.entry(block_signature.block_hash) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().proofs.extend(block_signature.proofs);
            }
            Entry::Vacant(_) => {
                self.signatures
                    .insert(block_signature.block_hash, block_signature);
            }
        }
    }

    /// Get signatures from the cache to be updated.
    /// If there are no signatures, create an empty signature to be updated.
    pub(crate) fn get_known_signatures(
        &self,
        block_hash: &BlockHash,
        block_era: EraId,
    ) -> BlockSignatures {
        match self.signatures.get(block_hash) {
            Some(signatures) => signatures.clone(),
            None => BlockSignatures::new(*block_hash, block_era),
        }
    }

    /// Returns whether finality signature is known already.
    pub(crate) fn known_signature(&self, fs: &FinalitySignature) -> bool {
        let FinalitySignature {
            block_hash,
            public_key,
            ..
        } = fs;
        self.signatures
            .get(block_hash)
            .map_or(false, |bs| bs.has_proof(public_key))
    }
}
