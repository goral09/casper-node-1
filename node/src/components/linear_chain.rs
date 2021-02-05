use std::{convert::Infallible, fmt::Display};

use tracing::{debug, error, info, warn};

use casper_types::{ProtocolVersion, SemVer};

use super::Component;
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
    types::{BlockByHeight, FinalitySignature},
    NodeRng,
};

use futures::FutureExt;

mod event;
mod signature_cache;
pub mod state;
pub use event::*;
pub(crate) use signature_cache::SignatureCache;
pub(crate) use state::{LinearChainOutcome, LinearChainState};

impl<I, REv> Component<REv> for LinearChainState<I>
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
                let (signatures, new_fs) = self.collect_pending_finality_signatures(
                    block.hash(),
                    block.header().era_id(),
                );
                self.signature_cache.insert(signatures.clone());
                let mut effects = Effects::new();
                effects.extend(effect_builder.put_signatures_to_storage(signatures).ignore());
                for fs in new_fs {
                    let message = Message::FinalitySignature(Box::new(fs.clone()));
                    effects.extend(effect_builder.broadcast_message(message).ignore());
                    effects.extend(effect_builder.announce_finality_signature(Box::new(fs)).ignore());
                }
                // Cache the signature as we expect more finality signatures to arrive soon.
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
                if let Some(outcome)= self.handle_finality_signature(fs.clone()) {
                    match outcome {
                        LinearChainOutcome::GetSignaturesFromStorage(block_hash) => effect_builder
                        .get_signatures_from_storage(block_hash)
                        .event(move |maybe_signatures| {
                            let maybe_box_signatures = maybe_signatures.map(Box::new);
                            Event::GetStoredFinalitySignaturesResult(fs, maybe_box_signatures)
                        }),
                        LinearChainOutcome::StoredFinalitySignatures(signatures) => effect_builder.immediately().event(move |_| {
                            Event::GetStoredFinalitySignaturesResult(fs, Some(Box::new(signatures)))
                        })
                    }
                } else {
                    Effects::new()
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
