use std::{
    collections::{hash_map::Entry, HashMap},
    convert::Infallible,
    fmt::Display,
    marker::PhantomData,
};

use datasize::DataSize;
use itertools::Itertools;
use tracing::{debug, error, info, warn};

use casper_types::{ProtocolVersion, PublicKey, SemVer, Signature};

use super::{consensus::EraId, Component};
use crate::{
    effect::{
        announcements::LinearChainAnnouncement,
        requests::{
            ConsensusRequest, ContractRuntimeRequest, LinearChainRequest, NetworkRequest,
            StorageRequest,
        },
        EffectBuilder, EffectExt, EffectOptionExt, EffectResultExt, Effects,
    },
    protocol::Message,
    types::{Block, BlockByHeight, BlockHash, BlockSignatures, FinalitySignature},
    NodeRng,
};

use futures::FutureExt;

mod event;
pub use event::*;

/// The maximum number of finality signatures from a single validator we keep in memory while
/// waiting for their block.
const MAX_PENDING_FINALITY_SIGNATURES_PER_VALIDATOR: usize = 1000;

#[derive(DataSize, Debug)]
struct SignatureCache {
    curr_era: EraId,
    signatures: HashMap<BlockHash, BlockSignatures>,
}

impl SignatureCache {
    fn new() -> Self {
        SignatureCache {
            curr_era: EraId(0),
            signatures: Default::default(),
        }
    }

    fn get(&mut self, hash: &BlockHash, _era_id: EraId) -> Option<BlockSignatures> {
        self.signatures.get(hash).cloned()
    }

    fn insert(&mut self, block_signature: BlockSignatures) {
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
    fn get_known_signatures(&self, block_hash: &BlockHash, block_era: EraId) -> BlockSignatures {
        match self.signatures.get(block_hash) {
            Some(signatures) => signatures.clone(),
            None => BlockSignatures::new(*block_hash, block_era),
        }
    }

    /// Returns whether finality signature is known already.
    fn known_signature(&self, fs: &FinalitySignature) -> bool {
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

#[derive(DataSize, Debug)]
pub(crate) struct LinearChain<I> {
    /// The most recently added block.
    latest_block: Option<Block>,
    /// Finality signatures to be inserted in a block once it is available.
    pending_finality_signatures: HashMap<PublicKey, HashMap<BlockHash, FinalitySignature>>,
    signature_cache: SignatureCache,
    _marker: PhantomData<I>,
}

impl<I> LinearChain<I> {
    pub fn new() -> Self {
        LinearChain {
            latest_block: None,
            pending_finality_signatures: HashMap::new(),
            signature_cache: SignatureCache::new(),
            _marker: PhantomData,
        }
    }

    // TODO: Remove once we can return all linear chain blocks from persistent storage.
    pub fn latest_block(&self) -> &Option<Block> {
        &self.latest_block
    }

    // Checks if we have already enqueued that finality signature.
    fn has_finality_signature(&self, fs: &FinalitySignature) -> bool {
        let creator = fs.public_key;
        let block_hash = fs.block_hash;
        self.pending_finality_signatures
            .get(&creator)
            .map_or(false, |sigs| sigs.contains_key(&block_hash))
    }

    /// Removes all entries for which there are no finality signatures.
    fn remove_empty_entries(&mut self) {
        self.pending_finality_signatures
            .retain(|_, sigs| !sigs.is_empty());
    }

    /// Adds pending finality signatures to the block; returns events to announce and broadcast
    /// them, and the updated block.
    fn collect_pending_finality_signatures<REv>(
        &mut self,
        block_hash: &BlockHash,
        block_era: EraId,
        effect_builder: EffectBuilder<REv>,
    ) -> (BlockSignatures, Effects<Event<I>>)
    where
        REv: From<StorageRequest>
            + From<ConsensusRequest>
            + From<NetworkRequest<I, Message>>
            + From<LinearChainAnnouncement>
            + Send,
        I: Display + Send + 'static,
    {
        let mut effects = Effects::new();
        let mut known_signatures = self
            .signature_cache
            .get_known_signatures(block_hash, block_era);
        let pending_sigs = self
            .pending_finality_signatures
            .values_mut()
            .filter_map(|sigs| sigs.remove(&block_hash).map(Box::new))
            .filter(|fs| !known_signatures.proofs.contains_key(&fs.public_key))
            .collect_vec();
        self.remove_empty_entries();
        // Add new signatures and send the updated block to storage.
        for fs in pending_sigs {
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
            let message = Message::FinalitySignature(fs.clone());
            effects.extend(effect_builder.broadcast_message(message).ignore());
            effects.extend(effect_builder.announce_finality_signature(fs).ignore());
        }
        (known_signatures, effects)
    }

    /// Adds finality signature to the collection of pending finality signatures.
    fn add_pending_finality_signature(&mut self, fs: FinalitySignature) {
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
    fn remove_from_pending_fs(&mut self, fs: &FinalitySignature) {
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

impl<I, REv> Component<REv> for LinearChain<I>
where
    REv: From<StorageRequest>
        + From<ConsensusRequest>
        + From<NetworkRequest<I, Message>>
        + From<LinearChainAnnouncement>
        + From<ContractRuntimeRequest>
        + Send,
    I: Display + Send + 'static,
{
    type Event = Event<I>;
    type ConstructionError = Infallible;

    fn handle_event(
        &mut self,
        effect_builder: EffectBuilder<REv>,
        _rng: &mut NodeRng,
        event: Self::Event,
    ) -> Effects<Self::Event> {
        match event {
            Event::Request(LinearChainRequest::BlockRequest(block_hash, sender)) => effect_builder
                .get_block_from_storage(block_hash)
                .event(move |maybe_block| {
                    Event::GetBlockResult(block_hash, maybe_block.map(Box::new), sender)
                }),
            Event::Request(LinearChainRequest::BlockAtHeightLocal(height, responder)) => {
                effect_builder
                    .get_block_at_height_from_storage(height)
                    .event(move |block| {
                        Event::GetBlockByHeightResultLocal(height, block.map(Box::new), responder)
                    })
            }
            Event::Request(LinearChainRequest::BlockAtHeight(height, sender)) => effect_builder
                .get_block_at_height_from_storage(height)
                .event(move |maybe_block| {
                    Event::GetBlockByHeightResult(height, maybe_block.map(Box::new), sender)
                }),
            Event::GetBlockByHeightResultLocal(_height, block, responder) => {
                responder.respond(block.map(|boxed| *boxed)).ignore()
            }
            Event::GetBlockByHeightResult(block_height, maybe_block, sender) => {
                let block_at_height = match maybe_block {
                    None => {
                        debug!("failed to get {} for {}", block_height, sender);
                        BlockByHeight::Absent(block_height)
                    }
                    Some(block) => BlockByHeight::new(*block),
                };
                match Message::new_get_response(&block_at_height) {
                    Ok(message) => effect_builder.send_message(sender, message).ignore(),
                    Err(error) => {
                        error!("failed to create get-response {}", error);
                        Effects::new()
                    }
                }
            }
            Event::GetBlockResult(block_hash, maybe_block, sender) => match maybe_block {
                None => {
                    debug!("failed to get {} for {}", block_hash, sender);
                    Effects::new()
                }
                Some(block) => match Message::new_get_response(&*block) {
                    Ok(message) => effect_builder.send_message(sender, message).ignore(),
                    Err(error) => {
                        error!("failed to create get-response {}", error);
                        Effects::new()
                    }
                },
            },
            Event::LinearChainBlock {
                block,
                execution_results,
            } => {
                let (signatures, mut effects) = self.collect_pending_finality_signatures(
                    block.hash(),
                    block.header().era_id(),
                    effect_builder,
                );
                // Cache the signature as we expect more finality signatures to arrive soon.
                self.signature_cache.insert(signatures);
                effects.extend(effect_builder.put_block_to_storage(block.clone()).event(
                    move |_| Event::PutBlockResult {
                        block,
                        execution_results,
                    },
                ));
                effects
            }
            Event::PutBlockResult {
                block,
                execution_results,
            } => {
                self.latest_block = Some(*block.clone());

                let block_header = block.take_header();
                let block_hash = block_header.hash();
                let era_id = block_header.era_id();
                let height = block_header.height();
                info!(%block_hash, %era_id, %height, "linear chain block stored");
                let mut effects = effect_builder
                    .put_execution_results_to_storage(block_hash, execution_results)
                    .ignore();
                effects.extend(
                    effect_builder
                        .handle_linear_chain_block(block_header.clone())
                        .map_some(move |fs| Event::FinalitySignatureReceived(Box::new(fs))),
                );
                effects.extend(
                    effect_builder
                        .announce_block_added(block_hash, block_header)
                        .ignore(),
                );
                effects
            }
            Event::FinalitySignatureReceived(fs) => {
                let FinalitySignature {
                    block_hash,
                    public_key,
                    era_id,
                    ..
                } = *fs;
                if let Err(err) = fs.verify() {
                    warn!(%block_hash, %public_key, %err, "received invalid finality signature");
                    return Effects::new();
                }
                if self.has_finality_signature(&fs) {
                    debug!(block_hash=%fs.block_hash, public_key=%fs.public_key,
                        "finality signature already pending");
                    return Effects::new();
                }
                if self.signature_cache.known_signature(&fs) {
                    debug!(block_hash=%fs.block_hash, public_key=%fs.public_key,
                        "finality signature is already known");
                    return Effects::new();
                }
                self.add_pending_finality_signature(*fs.clone());
                match self.signature_cache.get(&block_hash, era_id) {
                    None => effect_builder
                        .get_signatures_from_storage(block_hash)
                        .event(move |maybe_signatures| {
                            let maybe_box_signatures = maybe_signatures.map(Box::new);
                            Event::GetStoredFinalitySignaturesResult(fs, maybe_box_signatures)
                        }),
                    Some(signatures) => effect_builder.immediately().event(move |_| {
                        Event::GetStoredFinalitySignaturesResult(fs, Some(Box::new(signatures)))
                    }),
                }
            }
            Event::GetStoredFinalitySignaturesResult(fs, maybe_signatures) => {
                if let Some(signatures) = &maybe_signatures {
                    if signatures.era_id != fs.era_id {
                        warn!(public_key=%fs.public_key, expected=%signatures.era_id, got=%fs.era_id,
                            "finality signature with invalid era id.");
                        // TODO: Disconnect from the sender.
                        self.remove_from_pending_fs(&*fs);
                        return Effects::new();
                    }
                    // Populate cache so that next finality signatures don't have to read from the
                    // storage. If signature is already from cache then this will be a noop.
                    self.signature_cache.insert(*signatures.clone());
                }
                // Check if the validator is bonded in the era in which the block was created.
                effect_builder
                    .is_bonded_validator(fs.era_id, fs.public_key)
                    .map(|is_bonded| {
                        if is_bonded {
                            Ok((maybe_signatures, fs, is_bonded))
                        } else {
                            Err((maybe_signatures, fs))
                        }
                    })
            }
            .result(
                |(maybe_signatures, fs, is_bonded)| {
                    Event::IsBonded(maybe_signatures, fs, is_bonded)
                },
                |(maybe_signatures, fs)| Event::IsBondedFutureEra(maybe_signatures, fs),
            ),
            Event::IsBondedFutureEra(maybe_signatures, fs) => {
                match self.latest_block.as_ref() {
                    // If we don't have any block yet, we cannot determine who is bonded or not.
                    None => effect_builder
                        .immediately()
                        .event(move |_| Event::IsBonded(maybe_signatures, fs, false)),
                    Some(block) => {
                        let latest_header = block.header();
                        let state_root_hash = latest_header.state_root_hash();
                        // TODO: Use protocol version that is valid for the block's height.
                        let protocol_version = ProtocolVersion::new(SemVer::V1_0_0);
                        effect_builder
                            .is_bonded_in_future_era(
                                *state_root_hash,
                                fs.era_id,
                                protocol_version,
                                fs.public_key,
                            )
                            .map(|res| {
                                match res {
                                    // Promote this error to a non-error case.
                                    // It's not an error that we can't find the era that this
                                    // FinalitySignature is for.
                                    Err(error) if error.is_era_validators_missing() => Ok(false),
                                    _ => res,
                                }
                            })
                            .result(
                                |is_bonded| Event::IsBonded(maybe_signatures, fs, is_bonded),
                                |error| {
                                    error!(%error, "is_bonded_in_future_era returned an error.");
                                    panic!("couldn't check if validator is bonded")
                                },
                            )
                    }
                }
            }
            Event::IsBonded(Some(mut signatures), fs, true) => {
                // Known block and signature from a bonded validator.
                // Check if we had already seen this signature before.
                let signature_known = signatures
                    .proofs
                    .get(&fs.public_key)
                    .iter()
                    .any(|sig| *sig == &fs.signature);
                // If new, gossip and store.
                if signature_known {
                    self.remove_from_pending_fs(&*fs);
                    Effects::new()
                } else {
                    let message = Message::FinalitySignature(fs.clone());
                    let mut effects = effect_builder.broadcast_message(message).ignore();
                    effects.extend(
                        effect_builder
                            .announce_finality_signature(fs.clone())
                            .ignore(),
                    );
                    signatures.insert_proof(fs.public_key, fs.signature);
                    // Cache the results in case we receive the same finality signature before we
                    // manage to store it in the database.
                    self.signature_cache.insert(*signatures.clone());
                    debug!(hash=%signatures.block_hash, "storing finality signatures");
                    self.remove_from_pending_fs(&*fs);
                    effects.extend(
                        effect_builder
                            .put_signatures_to_storage(*signatures)
                            .ignore(),
                    );
                    effects
                }
            }
            Event::IsBonded(None, _, true) => {
                // Unknown block but validator is bonded.
                // We should finalize the same block eventually. Either in this or in the
                // next era.
                Effects::new()
            }
            Event::IsBonded(Some(_), fs, false) | Event::IsBonded(None, fs, false) => {
                self.remove_from_pending_fs(&fs);
                // Unknown validator.
                let FinalitySignature {
                    public_key,
                    block_hash,
                    ..
                } = *fs;
                warn!(
                    validator = %public_key,
                    %block_hash,
                    "Received a signature from a validator that is not bonded."
                );
                // TODO: Disconnect from the sender.
                Effects::new()
            }
        }
    }
}
