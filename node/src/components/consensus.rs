//! The consensus component. Provides distributed consensus among the nodes in the network.

mod candidate_block;
mod cl_context;
mod config;
mod consensus_protocol;
mod era_supervisor;
#[macro_use]
mod highway_core;
mod metrics;
mod protocols;
#[cfg(test)]
mod tests;
mod traits;

use std::{
    convert::Infallible,
    fmt::{self, Debug, Display, Formatter},
    time::Duration,
};

use datasize::DataSize;
use derive_more::From;
use hex_fmt::HexFmt;
use serde::{Deserialize, Serialize};
use tracing::error;

use casper_types::PublicKey;

use crate::{
    components::Component,
    effect::{
        announcements::ConsensusAnnouncement,
        requests::{
            self, BlockExecutorRequest, BlockProposerRequest, BlockValidationRequest,
            ChainspecLoaderRequest, ContractRuntimeRequest, NetworkRequest, StorageRequest,
        },
        EffectBuilder, Effects,
    },
    protocol::Message,
    types::{ActivationPoint, BlockHash, BlockHeader, ProtoBlock, Timestamp},
    NodeRng,
};

pub use config::Config;
pub(crate) use consensus_protocol::{BlockContext, EraEnd};
pub(crate) use era_supervisor::{EraId, EraSupervisor};
pub(crate) use protocols::highway::HighwayProtocol;
use traits::NodeIdT;

#[derive(DataSize, Clone, Serialize, Deserialize)]
pub enum ConsensusMessage {
    /// A protocol message, to be handled by the instance in the specified era.
    Protocol { era_id: EraId, payload: Vec<u8> },
    /// A request for evidence against the specified validator, from any era that is still bonded
    /// in `era_id`.
    EvidenceRequest { era_id: EraId, pub_key: PublicKey },
}

/// An ID to distinguish different timers. What they are used for is specific to each consensus
/// protocol implementation.
#[derive(DataSize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerId(pub u8);

/// An ID to distinguish queued actions. What they are used for is specific to each consensus
/// protocol implementation.
#[derive(DataSize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionId(pub u8);

/// Consensus component event.
#[derive(DataSize, Debug, From)]
pub enum Event<I> {
    /// An incoming network message.
    MessageReceived { sender: I, msg: ConsensusMessage },
    /// We connected to a peer.
    NewPeer(I),
    /// A scheduled event to be handled by a specified era
    Timer {
        era_id: EraId,
        timestamp: Timestamp,
        timer_id: TimerId,
    },
    /// A queued action to be handled by a specific era
    Action { era_id: EraId, action_id: ActionId },
    /// We are receiving the data we require to propose a new block
    NewProtoBlock {
        era_id: EraId,
        proto_block: ProtoBlock,
        block_context: BlockContext,
    },
    #[from]
    ConsensusRequest(requests::ConsensusRequest),
    /// The proto-block has been validated
    ResolveValidity {
        era_id: EraId,
        sender: I,
        proto_block: ProtoBlock,
        valid: bool,
    },
    /// Deactivate the era with the given ID, unless the number of faulty validators increases.
    DeactivateEra {
        era_id: EraId,
        faulty_num: usize,
        delay: Duration,
    },
    /// Event raised when a new era should be created: once we get the set of validators, the
    /// booking block hash and the seed from the key block
    CreateNewEra {
        /// The header of the switch block
        block_header: Box<BlockHeader>,
        /// Ok(block_hash) if the booking block was found, Err(height) if not
        booking_block_hash: Result<BlockHash, u64>,
    },
    /// An event instructing us to shutdown if the latest era received no votes
    Shutdown,
    /// An event fired when the joiner reactor transitions into validator.
    FinishedJoining(Timestamp),
    /// Got the result of checking for the next upgrade activation point.
    GotUpgradeActivationPoint(Option<ActivationPoint>),
}

impl Debug for ConsensusMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsensusMessage::Protocol { era_id, payload: _ } => {
                write!(f, "Protocol {{ era_id.0: {}, .. }}", era_id.0)
            }
            ConsensusMessage::EvidenceRequest { era_id, pub_key } => f
                .debug_struct("EvidenceRequest")
                .field("era_id.0", &era_id.0)
                .field("pub_key", pub_key)
                .finish(),
        }
    }
}

impl Display for ConsensusMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ConsensusMessage::Protocol { era_id, payload } => {
                write!(f, "protocol message {:10} in {}", HexFmt(payload), era_id)
            }
            ConsensusMessage::EvidenceRequest { era_id, pub_key } => write!(
                f,
                "request for evidence of fault by {} in {} or earlier",
                pub_key, era_id,
            ),
        }
    }
}

impl<I: Debug> Display for Event<I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Event::MessageReceived { sender, msg } => write!(f, "msg from {:?}: {}", sender, msg),
            Event::NewPeer(peer_id) => write!(f, "new peer connected: {:?}", peer_id),
            Event::Timer {
                era_id,
                timestamp,
                timer_id,
            } => write!(
                f,
                "timer (ID {}) for era {} scheduled for timestamp {}",
                timer_id.0, era_id.0, timestamp,
            ),
            Event::Action { era_id, action_id } => {
                write!(f, "action (ID {}) for era {}", action_id.0, era_id.0)
            }
            Event::NewProtoBlock {
                era_id,
                proto_block,
                block_context,
            } => write!(
                f,
                "New proto-block for era {:?}: {:?}, {:?}",
                era_id, proto_block, block_context
            ),
            Event::ConsensusRequest(request) => write!(
                f,
                "A request for consensus component hash been receieved: {:?}",
                request
            ),
            Event::ResolveValidity {
                era_id,
                sender,
                proto_block,
                valid,
            } => write!(
                f,
                "Proto-block received from {:?} for {} is {}: {:?}",
                sender,
                era_id,
                if *valid { "valid" } else { "invalid" },
                proto_block
            ),
            Event::DeactivateEra {
                era_id, faulty_num, ..
            } => write!(
                f,
                "Deactivate old era {} unless additional faults are observed; faults so far: {}",
                era_id.0, faulty_num
            ),
            Event::CreateNewEra {
                booking_block_hash,
                block_header,
            } => write!(
                f,
                "New era should be created; booking block hash: {:?}, switch block header: {:?}",
                booking_block_hash, block_header
            ),
            Event::Shutdown => write!(f, "Shutdown if current era is inactive"),
            Event::FinishedJoining(timestamp) => {
                write!(f, "The node finished joining the network at {}", timestamp)
            }
            Event::GotUpgradeActivationPoint(activation_point) => {
                write!(f, "new upgrade activation point: {:?}", activation_point)
            }
        }
    }
}

/// A helper trait whose bounds represent the requirements for a reactor event that `EraSupervisor`
/// can work with.
pub trait ReactorEventT<I>:
    From<Event<I>>
    + Send
    + From<NetworkRequest<I, Message>>
    + From<BlockProposerRequest>
    + From<ConsensusAnnouncement<I>>
    + From<BlockExecutorRequest>
    + From<BlockValidationRequest<ProtoBlock, I>>
    + From<StorageRequest>
    + From<ContractRuntimeRequest>
    + From<ChainspecLoaderRequest>
{
}

impl<REv, I> ReactorEventT<I> for REv where
    REv: From<Event<I>>
        + Send
        + From<NetworkRequest<I, Message>>
        + From<BlockProposerRequest>
        + From<ConsensusAnnouncement<I>>
        + From<BlockExecutorRequest>
        + From<BlockValidationRequest<ProtoBlock, I>>
        + From<StorageRequest>
        + From<ContractRuntimeRequest>
        + From<ChainspecLoaderRequest>
{
}

impl<I, REv> Component<REv> for EraSupervisor<I>
where
    I: NodeIdT,
    REv: ReactorEventT<I>,
{
    type Event = Event<I>;
    type ConstructionError = Infallible;

    fn handle_event(
        &mut self,
        effect_builder: EffectBuilder<REv>,
        mut rng: &mut NodeRng,
        event: Self::Event,
    ) -> Effects<Self::Event> {
        let mut handling_es = self.handling_wrapper(effect_builder, &mut rng);
        match event {
            Event::Timer {
                era_id,
                timestamp,
                timer_id,
            } => handling_es.handle_timer(era_id, timestamp, timer_id),
            Event::Action { era_id, action_id } => handling_es.handle_action(era_id, action_id),
            Event::MessageReceived { sender, msg } => handling_es.handle_message(sender, msg),
            Event::NewPeer(peer_id) => handling_es.handle_new_peer(peer_id),
            Event::NewProtoBlock {
                era_id,
                proto_block,
                block_context,
            } => handling_es.handle_new_proto_block(era_id, proto_block, block_context),
            Event::ConsensusRequest(requests::ConsensusRequest::HandleLinearBlock(
                block_header,
                responder,
            )) => handling_es.handle_linear_chain_block(*block_header, responder),
            Event::ResolveValidity {
                era_id,
                sender,
                proto_block,
                valid,
            } => handling_es.resolve_validity(era_id, sender, proto_block, valid),
            Event::DeactivateEra {
                era_id,
                faulty_num,
                delay,
            } => handling_es.handle_deactivate_era(era_id, faulty_num, delay),
            Event::CreateNewEra {
                block_header,
                booking_block_hash,
            } => {
                let booking_block_hash = booking_block_hash.unwrap_or_else(|height| {
                    error!(
                        "could not find the booking block at height {} for era {}",
                        height,
                        block_header.era_id().successor()
                    );
                    panic!("couldn't get the booking block hash");
                });
                handling_es.handle_create_new_era(*block_header, booking_block_hash)
            }
            Event::Shutdown => handling_es.shutdown_if_necessary(),
            Event::FinishedJoining(timestamp) => handling_es.finished_joining(timestamp),
            Event::GotUpgradeActivationPoint(activation_point) => {
                handling_es.got_upgrade_activation_point(activation_point)
            }
            Event::ConsensusRequest(requests::ConsensusRequest::IsBondedValidator(
                era_id,
                pk,
                responder,
            )) => handling_es.is_bonded_validator(era_id, pk, responder),
        }
    }
}
