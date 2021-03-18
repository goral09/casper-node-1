//! Consensus service is a component that will be communicating with the reactor.
//! It will receive events (like incoming message event or create new message event)
//! and propagate them to the underlying consensus protocol.
//! It tries to know as little as possible about the underlying consensus. The only thing
//! it assumes is the concept of era/epoch and that each era runs separate consensus instance.
//! Most importantly, it doesn't care about what messages it's forwarding.

mod era;
mod era_id;

use std::{
    collections::{hash_map::Entry, BTreeMap, HashMap, HashSet, VecDeque},
    convert::TryInto,
    fmt::{self, Debug, Formatter},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::Error;
use blake2::{
    digest::{Update, VariableOutput},
    VarBlake2b,
};
use datasize::DataSize;
use futures::FutureExt;
use itertools::Itertools;
use prometheus::Registry;
use rand::Rng;
use tracing::{debug, error, info, trace, warn};

use casper_types::{AsymmetricType, ProtocolVersion, PublicKey, SecretKey, U512};

use crate::{
    components::{
        consensus::{
            candidate_block::CandidateBlock,
            cl_context::{ClContext, Keypair},
            config::ProtocolConfig,
            consensus_protocol::{
                BlockContext, ConsensusProtocol, EraReport, FinalizedBlock as CpFinalizedBlock,
                ProtocolOutcome, ProtocolOutcomes,
            },
            metrics::ConsensusMetrics,
            traits::NodeIdT,
            ActionId, Config, ConsensusMessage, Event, ReactorEventT, TimerId,
        },
        contract_runtime::EraValidatorsRequest,
    },
    crypto::hash::Digest,
    effect::{
        requests::{ConsensusRequest, StorageRequest},
        EffectBuilder, EffectExt, Effects, Responder,
    },
    fatal,
    types::{
        ActivationPoint, Block, BlockHash, BlockHeader, BlockLike, FinalitySignature,
        FinalizedBlock, ProtoBlock, TimeDiff, Timestamp,
    },
    utils::WithDir,
    NodeRng,
};

pub use self::{era::Era, era_id::EraId};

/// The delay in milliseconds before we shutdown after the number of faulty validators exceeded the
/// fault tolerance threshold.
const FTT_EXCEEDED_SHUTDOWN_DELAY_MILLIS: u64 = 60 * 1000;

type ConsensusConstructor<I> = dyn Fn(
    Digest,                                       // the era's unique instance ID
    BTreeMap<PublicKey, U512>,                    // validator weights
    &HashSet<PublicKey>,                          // slashed validators that are banned in this era
    &ProtocolConfig,                              // the network's chainspec
    &Config,                                      // The consensus part of the node config.
    Option<&dyn ConsensusProtocol<I, ClContext>>, // previous era's consensus instance
    Timestamp,                                    // start time for this era
    u64,                                          // random seed
    Timestamp,                                    // now timestamp
) -> (
    Box<dyn ConsensusProtocol<I, ClContext>>,
    Vec<ProtocolOutcome<I, ClContext>>,
) + Send;

#[derive(DataSize)]
pub struct EraSupervisor<I> {
    /// A map of active consensus protocols.
    /// A value is a trait so that we can run different consensus protocol instances per era.
    ///
    /// This map always contains exactly `2 * bonded_eras + 1` entries, with the last one being the
    /// current one.
    active_eras: HashMap<EraId, Era<I>>,
    secret_signing_key: Arc<SecretKey>,
    pub(super) public_signing_key: PublicKey,
    current_era: EraId,
    protocol_config: ProtocolConfig,
    config: Config,
    #[data_size(skip)] // Negligible for most closures, zero for functions.
    new_consensus: Box<ConsensusConstructor<I>>,
    node_start_time: Timestamp,
    /// The height of the next block to be finalized.
    /// We keep that in order to be able to signal to the Block Proposer how many blocks have been
    /// finalized when we request a new block. This way the Block Proposer can know whether it's up
    /// to date, or whether it has to wait for more finalized blocks before responding.
    /// This value could be obtained from the consensus instance in a relevant era, but caching it
    /// here is the easiest way of achieving the desired effect.
    next_block_height: u64,
    /// The height of the next block to be executed. If this falls too far behind, we pause.
    next_executed_height: u64,
    #[data_size(skip)]
    metrics: ConsensusMetrics,
    // TODO: discuss this quick fix
    finished_joining: bool,
    /// The path to the folder where unit hash files will be stored.
    unit_hashes_folder: PathBuf,
    /// The next upgrade activation point. When the era immediately before the activation point is
    /// deactivated, the era supervisor indicates that the node should stop running to allow an
    /// upgrade.
    next_upgrade_activation_point: Option<ActivationPoint>,
    /// If true, the process should stop execution to allow an upgrade to proceed.
    stop_for_upgrade: bool,
    /// Set to true when InitializeEras is handled.
    /// TODO: A temporary field. Shouldn't be needed once the Joiner doesn't have a consensus
    /// component.
    is_initialized: bool,
    /// TODO: Remove once the era supervisor is removed from the Joiner reactor.
    pub(crate) enqueued_requests: VecDeque<ConsensusRequest>,
}

impl<I> Debug for EraSupervisor<I> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let ae: Vec<_> = self.active_eras.keys().collect();
        write!(formatter, "EraSupervisor {{ active_eras: {:?}, .. }}", ae)
    }
}

impl<I> EraSupervisor<I>
where
    I: NodeIdT,
{
    /// Creates a new `EraSupervisor`, starting in the indicated current era.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new<REv: ReactorEventT<I>>(
        timestamp: Timestamp,
        current_era: EraId,
        config: WithDir<Config>,
        effect_builder: EffectBuilder<REv>,
        protocol_config: ProtocolConfig,
        initial_state_root_hash: Digest,
        next_upgrade_activation_point: Option<ActivationPoint>,
        registry: &Registry,
        new_consensus: Box<ConsensusConstructor<I>>,
    ) -> Result<(Self, Effects<Event<I>>), Error> {
        if current_era < protocol_config.last_activation_point {
            panic!(
                "Current era ({:?}) is before the last activation point ({:?}) - no eras would \
                be instantiated!",
                current_era, protocol_config.last_activation_point
            );
        }
        let unit_hashes_folder = config.with_dir(config.value().unit_hashes_folder.clone());
        let (root, config) = config.into_parts();
        let secret_signing_key = Arc::new(config.secret_key_path.clone().load(root)?);
        let public_signing_key = PublicKey::from(secret_signing_key.as_ref());
        info!(our_id = %public_signing_key, "EraSupervisor pubkey",);
        let metrics = ConsensusMetrics::new(registry)
            .expect("failure to setup and register ConsensusMetrics");
        let protocol_version = ProtocolVersion::from_parts(
            protocol_config.protocol_version.major as u32,
            protocol_config.protocol_version.minor as u32,
            protocol_config.protocol_version.patch as u32,
        );
        let activation_era_id = protocol_config.last_activation_point;
        let auction_delay = protocol_config.auction_delay;

        let era_supervisor = Self {
            active_eras: Default::default(),
            secret_signing_key,
            public_signing_key,
            current_era,
            protocol_config,
            config,
            new_consensus,
            node_start_time: Timestamp::now(),
            next_block_height: 0,
            metrics,
            finished_joining: false,
            unit_hashes_folder,
            next_upgrade_activation_point,
            stop_for_upgrade: false,
            next_executed_height: 0,
            is_initialized: false,
            enqueued_requests: Default::default(),
        };

        let bonded_eras = era_supervisor.bonded_eras();
        let era_ids: Vec<EraId> = era_supervisor
            .iter_past(current_era, era_supervisor.bonded_eras() * 3)
            .collect();

        // Asynchronously collect the information needed to initialize all recent eras.
        let effects = async move {
            info!(?era_ids, "collecting key blocks and booking blocks");

            let key_blocks = effect_builder
                .collect_key_blocks(era_ids.iter().cloned())
                .await
                .expect("should have all the key blocks in storage");

            let booking_blocks = collect_booking_block_hashes(
                effect_builder,
                era_ids.clone(),
                auction_delay,
                activation_era_id,
            )
            .await;

            if current_era > activation_era_id + bonded_eras * 2 {
                // All eras can be initialized using the key blocks only.
                (key_blocks, booking_blocks, Default::default())
            } else {
                // We need the validator set for the activation era from some protocol state.
                let state_root_hash = if activation_era_id == current_era {
                    // The activation era is the current one, so the initial state root hash
                    // contains its validator set.
                    initial_state_root_hash
                } else if activation_era_id.is_genesis() {
                    // To initialize the first era, we can use the global state of the first block.
                    *effect_builder
                        .get_block_at_height_local(0)
                        .await
                        .expect("missing block in genesis era")
                        .state_root_hash()
                } else {
                    // The first block in the activation era contains the validator set.
                    let block_height = if activation_era_id.is_genesis() {
                        0
                    } else {
                        &key_blocks[&activation_era_id].height() + 1
                    };
                    *effect_builder
                        .get_block_at_height_local(block_height)
                        .await
                        .expect("missing block in activation era")
                        .state_root_hash()
                };
                let validators_request =
                    EraValidatorsRequest::new(state_root_hash.into(), protocol_version);
                let validators = effect_builder
                    .get_era_validators(validators_request)
                    .await
                    .expect("get validator map from global state")
                    .remove(&activation_era_id.0)
                    .expect("get validators for activation era");
                (key_blocks, booking_blocks, validators)
            }
        }
        .event(
            move |(key_blocks, booking_blocks, validators)| Event::InitializeEras {
                key_blocks,
                booking_blocks,
                validators,
                timestamp,
            },
        );

        Ok((era_supervisor, effects))
    }

    /// Returns a temporary container with this `EraSupervisor`, `EffectBuilder` and random number
    /// generator, for handling events.
    pub(super) fn handling_wrapper<'a, REv: ReactorEventT<I>>(
        &'a mut self,
        effect_builder: EffectBuilder<REv>,
        rng: &'a mut NodeRng,
    ) -> EraSupervisorHandlingWrapper<'a, I, REv> {
        EraSupervisorHandlingWrapper {
            era_supervisor: self,
            effect_builder,
            rng,
        }
    }

    fn era_seed(booking_block_hash: BlockHash, key_block_seed: Digest) -> u64 {
        let mut result = [0; Digest::LENGTH];
        let mut hasher = VarBlake2b::new(Digest::LENGTH).expect("should create hasher");

        hasher.update(booking_block_hash);
        hasher.update(key_block_seed);

        hasher.finalize_variable(|slice| {
            result.copy_from_slice(slice);
        });

        u64::from_le_bytes(result[0..std::mem::size_of::<u64>()].try_into().unwrap())
    }

    /// Returns an iterator over era IDs of `num_eras` past eras, plus the provided one.
    pub(crate) fn iter_past(&self, era_id: EraId, num_eras: u64) -> impl Iterator<Item = EraId> {
        (self
            .protocol_config
            .last_activation_point
            .max(era_id.saturating_sub(num_eras))
            .0..=era_id.0)
            .map(EraId)
    }

    /// Returns an iterator over era IDs of `num_eras` past eras, excluding the provided one.
    pub(crate) fn iter_past_other(
        &self,
        era_id: EraId,
        num_eras: u64,
    ) -> impl Iterator<Item = EraId> {
        (self
            .protocol_config
            .last_activation_point
            .max(era_id.saturating_sub(num_eras))
            .0..era_id.0)
            .map(EraId)
    }

    /// Starts a new era; panics if it already exists.
    #[allow(clippy::too_many_arguments)] // FIXME
    fn new_era(
        &mut self,
        era_id: EraId,
        timestamp: Timestamp,
        validators: BTreeMap<PublicKey, U512>,
        newly_slashed: Vec<PublicKey>,
        slashed: HashSet<PublicKey>,
        seed: u64,
        start_time: Timestamp,
        start_height: u64,
    ) -> Vec<ProtocolOutcome<I, ClContext>> {
        if self.active_eras.contains_key(&era_id) {
            panic!("{} already exists", era_id);
        }
        self.current_era = era_id;
        self.metrics.current_era.set(self.current_era.0 as i64);
        let instance_id = instance_id(&self.protocol_config, era_id);

        info!(
            ?validators,
            %start_time,
            %timestamp,
            %start_height,
            %instance_id,
            era = era_id.0,
            "starting era",
        );

        // Activate the era if this node was already running when the era began, it is still
        // ongoing based on its minimum duration, and we are one of the validators.
        let our_id = self.public_signing_key;
        let should_activate = if !validators.contains_key(&our_id) {
            info!(era = era_id.0, %our_id, "not voting; not a validator");
            false
        } else if !self.finished_joining {
            info!(era = era_id.0, %our_id, "not voting; still joining");
            false
        } else {
            info!(era = era_id.0, %our_id, "start voting");
            true
        };

        let prev_era = era_id
            .checked_sub(1)
            .and_then(|last_era_id| self.active_eras.get(&last_era_id));

        let (mut consensus, mut outcomes) = (self.new_consensus)(
            instance_id,
            validators.clone(),
            &slashed,
            &self.protocol_config,
            &self.config,
            prev_era.map(|era| &*era.consensus),
            start_time,
            seed,
            timestamp,
        );

        if should_activate {
            let secret = Keypair::new(self.secret_signing_key.clone(), our_id);
            let unit_hash_file = self.unit_hashes_folder.join(format!(
                "unit_hash_{:?}_{}.dat",
                instance_id,
                self.public_signing_key.to_hex()
            ));
            outcomes.extend(consensus.activate_validator(
                our_id,
                secret,
                timestamp,
                Some(unit_hash_file),
            ))
        }

        let era = Era::new(
            consensus,
            start_time,
            start_height,
            newly_slashed,
            slashed,
            validators,
        );
        let _ = self.active_eras.insert(era_id, era);
        let oldest_bonded_era_id = oldest_bonded_era(&self.protocol_config, era_id);
        // Clear the obsolete data from the era whose validators are unbonded now. We only retain
        // the information necessary to validate evidence that units in still-bonded eras may refer
        // to for cross-era slashing.
        if let Some(evidence_only_era_id) = oldest_bonded_era_id.checked_sub(1) {
            trace!(era = evidence_only_era_id.0, "clearing unbonded era");
            if let Some(era) = self.active_eras.get_mut(&evidence_only_era_id) {
                era.consensus.set_evidence_only();
            }
        }
        // Remove the era that has become obsolete now: The oldest bonded era could still receive
        // units that refer to evidence from any era that was bonded when it was the current one.
        let oldest_evidence_era_id = oldest_bonded_era(&self.protocol_config, oldest_bonded_era_id);
        if let Some(obsolete_era_id) = oldest_evidence_era_id.checked_sub(1) {
            trace!(era = obsolete_era_id.0, "removing obsolete era");
            self.active_eras.remove(&obsolete_era_id);
        }

        outcomes
    }

    /// Returns `true` if the specified era is active and bonded.
    fn is_bonded(&self, era_id: EraId) -> bool {
        era_id.0 + self.bonded_eras() >= self.current_era.0 && era_id <= self.current_era
    }

    /// Returns whether the validator with the given public key is bonded in that era.
    fn is_validator_in(&self, pub_key: &PublicKey, era_id: EraId) -> bool {
        let has_validator = |era: &Era<I>| era.validators().contains_key(&pub_key);
        self.active_eras.get(&era_id).map_or(false, has_validator)
    }

    /// Returns the most recent active era.
    #[cfg(test)]
    pub(crate) fn current_era(&self) -> EraId {
        self.current_era
    }

    /// To be called when we transition from the joiner to the validator reactor.
    pub(crate) fn finished_joining(
        &mut self,
        now: Timestamp,
        maybe_header: Option<Box<BlockHeader>>,
    ) -> ProtocolOutcomes<I, ClContext> {
        let next_height = maybe_header.map(|hdr| hdr.height() + 1).unwrap_or(0);
        self.next_executed_height = self.next_executed_height.max(next_height);
        self.next_block_height = self.next_block_height.max(next_height);
        self.finished_joining = true;
        let secret = Keypair::new(self.secret_signing_key.clone(), self.public_signing_key);
        let public_key = self.public_signing_key;
        let unit_hashes_folder = self.unit_hashes_folder.clone();
        self.active_eras
            .get_mut(&self.current_era)
            .map(|era| {
                if era.validators().contains_key(&public_key) {
                    let instance_id = *era.consensus.instance_id();
                    let unit_hash_file = unit_hashes_folder.join(format!(
                        "unit_hash_{:?}_{}.dat",
                        instance_id,
                        public_key.to_hex()
                    ));
                    era.consensus
                        .activate_validator(public_key, secret, now, Some(unit_hash_file))
                } else {
                    Vec::new()
                }
            })
            .unwrap_or_default()
    }

    pub(crate) fn stop_for_upgrade(&self) -> bool {
        self.stop_for_upgrade
    }

    /// Updates `next_executed_height` based on the given block header, and unpauses consensus if
    /// block execution has caught up with finalization.
    fn executed_block(&mut self, block_header: &BlockHeader) {
        self.next_executed_height = self.next_executed_height.max(block_header.height() + 1);
        self.update_consensus_pause();
    }

    /// Pauses or unpauses consensus: Whenever the last executed block is too far behind the last
    /// finalized block, we suspend consensus.
    fn update_consensus_pause(&mut self) {
        let paused = self
            .next_block_height
            .saturating_sub(self.next_executed_height)
            > self.config.max_execution_delay;
        match self.active_eras.get_mut(&self.current_era) {
            Some(era) => era.set_paused(paused),
            None => error!(era = self.current_era.0, "current era not initialized"),
        }
    }

    pub(crate) fn recreate_timers<'a, REv: ReactorEventT<I>>(
        &'a mut self,
        effect_builder: EffectBuilder<REv>,
        rng: &'a mut NodeRng,
    ) -> Effects<Event<I>> {
        let current_era = self.current_era;
        trace!(?current_era, "recreating timers");
        let outcomes = self.active_eras[&current_era].consensus.recreate_timers();
        self.handling_wrapper(effect_builder, rng)
            .handle_consensus_outcomes(current_era, outcomes)
    }

    /// Returns true if initialization of the first eras is finished.
    pub(crate) fn is_initialized(&self) -> bool {
        self.is_initialized
    }

    fn handle_initialize_eras(
        &mut self,
        key_blocks: HashMap<EraId, BlockHeader>,
        booking_blocks: HashMap<EraId, BlockHash>,
        activation_era_validators: BTreeMap<PublicKey, U512>,
        timestamp: Timestamp,
    ) -> HashMap<EraId, ProtocolOutcomes<I, ClContext>> {
        let mut result_map = HashMap::new();

        for era_id in self.iter_past(self.current_era, self.bonded_eras() * 2) {
            let newly_slashed;
            let validators;
            let start_height;
            let era_start_time;
            let seed;

            let booking_block_hash = booking_blocks
                .get(&era_id)
                .expect("should have booking block");

            if era_id.is_genesis() {
                newly_slashed = vec![];
                // The validator set was read from the global state: there's no key block for era 0.
                validators = activation_era_validators.clone();
                start_height = 0;
                era_start_time = self
                    .protocol_config
                    .genesis_timestamp
                    .expect("must have genesis start time if era ID is 0");
                seed = 0;
            } else {
                // If this is not era 0, there must be a key block for it.
                let key_block = key_blocks.get(&era_id).expect("missing key block");
                start_height = key_block.height() + 1;
                era_start_time = key_block.timestamp();
                seed = Self::era_seed(*booking_block_hash, key_block.accumulated_seed());
                if era_id == self.protocol_config.last_activation_point {
                    // After an upgrade or emergency restart, we don't do cross-era slashing.
                    newly_slashed = vec![];
                    // And we read the validator sets from the global state, because the key block
                    // might have been overwritten by the upgrade/restart.
                    validators = activation_era_validators.clone();
                } else {
                    // If it's neither genesis nor upgrade nor restart, we use the validators from
                    // the key block and ban validators that were slashed in previous eras.
                    newly_slashed = key_block
                        .era_end()
                        .expect("key block must be a switch block")
                        .equivocators
                        .clone();
                    validators = key_block
                        .next_era_validator_weights()
                        .expect("missing validators from key block")
                        .clone();
                }
            }

            let slashed = self
                .iter_past(era_id, self.bonded_eras())
                .filter_map(|old_id| key_blocks.get(&old_id).and_then(|bhdr| bhdr.era_end()))
                .flat_map(|era_end| era_end.equivocators.clone())
                .collect();

            let results = self.new_era(
                era_id,
                timestamp,
                validators,
                newly_slashed,
                slashed,
                seed,
                era_start_time,
                start_height,
            );
            result_map.insert(era_id, results);
        }

        self.is_initialized = true;
        let active_era_outcomes = self.active_eras[&self.current_era]
            .consensus
            .handle_is_current();
        match result_map.entry(self.current_era) {
            Entry::Occupied(mut current) => {
                let _ = current.get_mut().extend(active_era_outcomes);
            }
            Entry::Vacant(vacant) => {
                let _ = vacant.insert(active_era_outcomes);
            }
        };
        self.next_block_height = self.active_eras[&self.current_era].start_height;
        result_map
    }

    /// The number of past eras whose validators are still bonded. After this many eras, a former
    /// validator is allowed to withdraw their stake, so their signature can't be trusted anymore.
    ///
    /// A node keeps `2 * bonded_eras` past eras around, because the oldest bonded era could still
    /// receive blocks that refer to `bonded_eras` before that.
    fn bonded_eras(&self) -> u64 {
        bonded_eras(&self.protocol_config)
    }
}

/// Returns an era ID in which the booking block for `era_id` lives, if we can use it.
/// Booking block for era N is the switch block (the last block) in era N – AUCTION_DELAY - 1.
/// To find it, we get the start height of era N - AUCTION_DELAY and subtract 1.
/// We make sure not to use an era ID below the last upgrade activation point, because we will
/// not have instances of eras from before that.
///
/// We can't use it if it is:
/// * before Genesis
/// * before upgrade
/// * before emergency restart
/// In those cases, returns `None`.
fn valid_booking_block_era_id(
    era_id: EraId,
    auction_delay: u64,
    last_activation_point: EraId,
) -> Option<EraId> {
    let after_booking_era_id = era_id.saturating_sub(auction_delay);

    // If we would have gone below the last activation point (the first `AUCTION_DELAY ` eras after
    // an upgrade), we return `None` as there are no booking blocks there that we can use – we
    // can't use anything from before an upgrade.
    // NOTE that it's OK if `booking_era_id` == `last_activation_point`.
    (after_booking_era_id > last_activation_point).then(|| after_booking_era_id.saturating_sub(1))
}

/// Returns a booking block hash for `era_id`.
async fn get_booking_block_hash<REv>(
    effect_builder: EffectBuilder<REv>,
    era_id: EraId,
    auction_delay: u64,
    last_activation_point: EraId,
) -> BlockHash
where
    REv: From<StorageRequest>,
{
    if let Some(booking_block_era_id) =
        valid_booking_block_era_id(era_id, auction_delay, last_activation_point)
    {
        match effect_builder
            .get_switch_block_at_era_id_from_storage(booking_block_era_id)
            .await
        {
            Some(block) => *block.hash(),
            None => {
                error!(
                    ?era_id,
                    ?booking_block_era_id,
                    "booking block for era must exist"
                );
                panic!("booking block not found in storage");
            }
        }
    } else {
        // If there's no booking block for the `era_id`
        // (b/c it would have been from before Genesis, upgrade or emergency restart),
        // use a "zero" block hash. This should not hurt the security of the leader selection
        // algorithm.
        BlockHash::default()
    }
}

/// Returns booking block hashes for the eras.
async fn collect_booking_block_hashes<REv>(
    effect_builder: EffectBuilder<REv>,
    era_ids: Vec<EraId>,
    auction_delay: u64,
    last_activation_point: EraId,
) -> HashMap<EraId, BlockHash>
where
    REv: From<StorageRequest>,
{
    let mut booking_block_hashes: HashMap<EraId, BlockHash> = HashMap::new();

    for era_id in era_ids {
        let booking_block_hash =
            get_booking_block_hash(effect_builder, era_id, auction_delay, last_activation_point)
                .await;
        booking_block_hashes.insert(era_id, booking_block_hash);
    }

    booking_block_hashes
}

/// A mutable `EraSupervisor` reference, together with an `EffectBuilder`.
///
/// This is a short-lived convenience type to avoid passing the effect builder through lots of
/// message calls, and making every method individually generic in `REv`. It is only instantiated
/// for the duration of handling a single event.
pub(super) struct EraSupervisorHandlingWrapper<'a, I, REv: 'static> {
    pub(super) era_supervisor: &'a mut EraSupervisor<I>,
    pub(super) effect_builder: EffectBuilder<REv>,
    pub(super) rng: &'a mut NodeRng,
}

impl<'a, I, REv> EraSupervisorHandlingWrapper<'a, I, REv>
where
    I: NodeIdT,
    REv: ReactorEventT<I>,
{
    /// Applies `f` to the consensus protocol of the specified era.
    fn delegate_to_era<F>(&mut self, era_id: EraId, f: F) -> Effects<Event<I>>
    where
        F: FnOnce(&mut dyn ConsensusProtocol<I, ClContext>) -> Vec<ProtocolOutcome<I, ClContext>>,
    {
        match self.era_supervisor.active_eras.get_mut(&era_id) {
            None => {
                if era_id > self.era_supervisor.current_era {
                    info!(era = era_id.0, "received message for future era");
                } else {
                    info!(era = era_id.0, "received message for obsolete era");
                }
                Effects::new()
            }
            Some(era) => {
                let outcomes = f(&mut *era.consensus);
                self.handle_consensus_outcomes(era_id, outcomes)
            }
        }
    }

    pub(super) fn handle_timer(
        &mut self,
        era_id: EraId,
        timestamp: Timestamp,
        timer_id: TimerId,
    ) -> Effects<Event<I>> {
        self.delegate_to_era(era_id, move |consensus| {
            consensus.handle_timer(timestamp, timer_id)
        })
    }

    pub(super) fn handle_action(
        &mut self,
        era_id: EraId,
        action_id: ActionId,
    ) -> Effects<Event<I>> {
        self.delegate_to_era(era_id, move |consensus| consensus.handle_action(action_id))
    }

    pub(super) fn handle_message(&mut self, sender: I, msg: ConsensusMessage) -> Effects<Event<I>> {
        match msg {
            ConsensusMessage::Protocol { era_id, payload } => {
                // If the era is already unbonded, only accept new evidence, because still-bonded
                // eras could depend on that.
                trace!(era = era_id.0, "received a consensus message");
                self.delegate_to_era(era_id, move |consensus| {
                    consensus.handle_message(sender, payload)
                })
            }
            ConsensusMessage::EvidenceRequest { era_id, pub_key } => {
                if !self.era_supervisor.is_bonded(era_id) {
                    trace!(era = era_id.0, "not handling message; era too old");
                    return Effects::new();
                }
                self.era_supervisor
                    .iter_past(era_id, self.era_supervisor.bonded_eras())
                    .flat_map(|e_id| {
                        self.delegate_to_era(e_id, |consensus| {
                            consensus.request_evidence(sender.clone(), &pub_key)
                        })
                    })
                    .collect()
            }
        }
    }

    pub(super) fn handle_new_peer(&mut self, peer_id: I) -> Effects<Event<I>> {
        self.delegate_to_era(self.era_supervisor.current_era, move |consensus| {
            consensus.handle_new_peer(peer_id)
        })
    }

    pub(super) fn handle_new_proto_block(
        &mut self,
        era_id: EraId,
        proto_block: ProtoBlock,
        block_context: BlockContext,
    ) -> Effects<Event<I>> {
        if !self.era_supervisor.is_bonded(era_id) {
            warn!(era = era_id.0, "new proto block in outdated era");
            return Effects::new();
        }
        let accusations = self
            .era_supervisor
            .iter_past(era_id, self.era_supervisor.bonded_eras())
            .flat_map(|e_id| self.era(e_id).consensus.validators_with_evidence())
            .unique()
            .filter(|pub_key| !self.era(era_id).slashed.contains(pub_key))
            .cloned()
            .collect();
        let candidate_block =
            CandidateBlock::new(proto_block, block_context.timestamp(), accusations);
        self.delegate_to_era(era_id, move |consensus| {
            consensus.propose(candidate_block, block_context)
        })
    }

    pub(super) fn handle_linear_chain_block(
        &mut self,
        block: Block,
        responder: Responder<Option<FinalitySignature>>,
    ) -> Effects<Event<I>> {
        // TODO: Delete once `EraSupervisor` gets removed from the joiner reactor.
        if !self.era_supervisor.is_initialized() {
            // enqueue
            self.era_supervisor
                .enqueued_requests
                .push_back(ConsensusRequest::HandleLinearBlock(
                    Box::new(block),
                    responder,
                ));
            return Effects::new();
        }
        let our_pk = self.era_supervisor.public_signing_key;
        let our_sk = self.era_supervisor.secret_signing_key.clone();
        let era_id = block.header().era_id();
        self.era_supervisor.executed_block(block.header());
        let maybe_fin_sig = if self.era_supervisor.is_validator_in(&our_pk, era_id) {
            let block_hash = block.hash();
            Some(FinalitySignature::new(*block_hash, era_id, &our_sk, our_pk))
        } else {
            None
        };
        let mut effects = responder.respond(maybe_fin_sig).ignore();
        if era_id < self.era_supervisor.current_era {
            trace!(era = era_id.0, "executed block in old era");
            return effects;
        }
        if block.header().is_switch_block() && !self.should_upgrade_after(&era_id) {
            // if the block is a switch block, we have to get the validators for the new era and
            // create it, before we can say we handled the block
            let new_era_id = era_id.successor();
            let effect = get_booking_block_hash(
                self.effect_builder,
                new_era_id,
                self.era_supervisor.protocol_config.auction_delay,
                self.era_supervisor.protocol_config.last_activation_point,
            )
            .event(|booking_block_hash| Event::CreateNewEra {
                block: Box::new(block),
                booking_block_hash: Ok(booking_block_hash),
            });
            effects.extend(effect);
        } else {
            // if it's not a switch block, we can already declare it handled
            effects.extend(self.effect_builder.announce_block_handled(block).ignore());
        }
        effects
    }

    pub(super) fn handle_deactivate_era(
        &mut self,
        era_id: EraId,
        old_faulty_num: usize,
        delay: Duration,
    ) -> Effects<Event<I>> {
        let era = if let Some(era) = self.era_supervisor.active_eras.get_mut(&era_id) {
            era
        } else {
            warn!(era = era_id.0, "trying to deactivate obsolete era");
            return Effects::new();
        };
        let faulty_num = era.consensus.validators_with_evidence().len();
        if faulty_num == old_faulty_num {
            info!(era = era_id.0, "stop voting in era");
            era.consensus.deactivate_validator();
            if self.should_upgrade_after(&era_id) {
                // If the next era is at or after the upgrade activation point, stop the node.
                info!(era = era_id.0, "shutting down for upgrade");
                self.era_supervisor.stop_for_upgrade = true;
            }
            Effects::new()
        } else {
            let deactivate_era = move |_| Event::DeactivateEra {
                era_id,
                faulty_num,
                delay,
            };
            self.effect_builder.set_timeout(delay).event(deactivate_era)
        }
    }

    pub(super) fn handle_initialize_eras(
        &mut self,
        key_blocks: HashMap<EraId, BlockHeader>,
        booking_blocks: HashMap<EraId, BlockHash>,
        validators: BTreeMap<PublicKey, U512>,
        timestamp: Timestamp,
    ) -> Effects<Event<I>> {
        let result_map = self.era_supervisor.handle_initialize_eras(
            key_blocks,
            booking_blocks,
            validators,
            timestamp,
        );

        let effects = result_map
            .into_iter()
            .flat_map(|(era_id, results)| self.handle_consensus_outcomes(era_id, results))
            .collect();

        info!("finished initializing era supervisor");
        info!(?self.era_supervisor, "current eras");

        effects
    }

    /// Creates a new era.
    pub(super) fn handle_create_new_era(
        &mut self,
        switch_block: Block,
        booking_block_hash: BlockHash,
    ) -> Effects<Event<I>> {
        let (era_end, next_era_validators_weights) = match (
            switch_block.header().era_end(),
            switch_block.header().next_era_validator_weights(),
        ) {
            (Some(era_end), Some(next_era_validator_weights)) => {
                (era_end, next_era_validator_weights)
            }
            _ => {
                return fatal!(
                    self.effect_builder,
                    "attempted to create a new era with a non-switch block: {}",
                    switch_block
                )
                .ignore()
            }
        };
        let newly_slashed = era_end.equivocators.clone();
        let era_id = switch_block.header().era_id().successor();
        info!(era = era_id.0, "era created");
        let seed = EraSupervisor::<I>::era_seed(
            booking_block_hash,
            switch_block.header().accumulated_seed(),
        );
        trace!(%seed, "the seed for {}: {}", era_id, seed);
        let slashed = self
            .era_supervisor
            .iter_past_other(era_id, self.era_supervisor.bonded_eras())
            .flat_map(|e_id| &self.era_supervisor.active_eras[&e_id].newly_slashed)
            .chain(&newly_slashed)
            .cloned()
            .collect();
        let outcomes = self.era_supervisor.new_era(
            era_id,
            Timestamp::now(), // TODO: This should be passed in.
            next_era_validators_weights.clone(),
            newly_slashed,
            slashed,
            seed,
            switch_block.header().timestamp(),
            switch_block.height() + 1,
        );
        let mut effects = self.handle_consensus_outcomes(era_id, outcomes);
        effects.extend(
            self.effect_builder
                .announce_block_handled(switch_block)
                .ignore(),
        );
        effects
    }

    pub(super) fn resolve_validity(
        &mut self,
        era_id: EraId,
        sender: I,
        proto_block: ProtoBlock,
        timestamp: Timestamp,
        valid: bool,
    ) -> Effects<Event<I>> {
        self.era_supervisor.metrics.proposed_block();
        let mut effects = Effects::new();
        if !valid {
            warn!(
                %sender,
                era = %era_id.0,
                "invalid consensus value; disconnecting from the sender"
            );
            effects.extend(self.disconnect(sender));
        }
        let candidate_blocks = if let Some(era) = self.era_supervisor.active_eras.get_mut(&era_id) {
            era.resolve_validity(&proto_block, timestamp, valid)
        } else {
            return effects;
        };
        for candidate_block in candidate_blocks {
            effects.extend(self.delegate_to_era(era_id, |consensus| {
                consensus.resolve_validity(&candidate_block, valid)
            }));
        }
        effects
    }

    fn handle_consensus_outcomes<T>(&mut self, era_id: EraId, outcomes: T) -> Effects<Event<I>>
    where
        T: IntoIterator<Item = ProtocolOutcome<I, ClContext>>,
    {
        outcomes
            .into_iter()
            .flat_map(|result| self.handle_consensus_outcome(era_id, result))
            .collect()
    }

    /// Returns `true` if any of the most recent eras has evidence against the validator with key
    /// `pub_key`.
    fn has_evidence(&self, era_id: EraId, pub_key: PublicKey) -> bool {
        self.era_supervisor
            .iter_past(era_id, self.era_supervisor.bonded_eras())
            .any(|eid| self.era(eid).consensus.has_evidence(&pub_key))
    }

    /// Returns the era with the specified ID. Panics if it does not exist.
    fn era(&self, era_id: EraId) -> &Era<I> {
        &self.era_supervisor.active_eras[&era_id]
    }

    /// Returns the era with the specified ID mutably. Panics if it does not exist.
    fn era_mut(&mut self, era_id: EraId) -> &mut Era<I> {
        self.era_supervisor.active_eras.get_mut(&era_id).unwrap()
    }

    fn handle_consensus_outcome(
        &mut self,
        era_id: EraId,
        consensus_result: ProtocolOutcome<I, ClContext>,
    ) -> Effects<Event<I>> {
        match consensus_result {
            ProtocolOutcome::InvalidIncomingMessage(_, sender, error) => {
                warn!(
                    %sender,
                    %error,
                    "invalid incoming message to consensus instance; disconnecting from the sender"
                );
                self.disconnect(sender)
            }
            ProtocolOutcome::Disconnect(sender) => {
                warn!(
                    %sender,
                    "disconnecting from the sender of invalid data"
                );
                self.disconnect(sender)
            }
            ProtocolOutcome::CreatedGossipMessage(out_msg) => {
                // TODO: we'll want to gossip instead of broadcast here
                self.effect_builder
                    .broadcast_message(era_id.message(out_msg).into())
                    .ignore()
            }
            ProtocolOutcome::CreatedTargetedMessage(out_msg, to) => self
                .effect_builder
                .send_message(to, era_id.message(out_msg).into())
                .ignore(),
            ProtocolOutcome::ScheduleTimer(timestamp, timer_id) => {
                let timediff = timestamp.saturating_diff(Timestamp::now());
                self.effect_builder
                    .set_timeout(timediff.into())
                    .event(move |_| Event::Timer {
                        era_id,
                        timestamp,
                        timer_id,
                    })
            }
            ProtocolOutcome::QueueAction(action_id) => self
                .effect_builder
                .immediately()
                .event(move |()| Event::Action { era_id, action_id }),
            ProtocolOutcome::CreateNewBlock {
                block_context,
                past_values,
            } => {
                let past_deploys = past_values
                    .iter()
                    .flat_map(|candidate| BlockLike::deploys(candidate.proto_block()))
                    .cloned()
                    .collect();
                self.effect_builder
                    .request_proto_block(
                        block_context,
                        past_deploys,
                        self.era_supervisor.next_block_height,
                        self.rng.gen(),
                    )
                    .event(move |(proto_block, block_context)| Event::NewProtoBlock {
                        era_id,
                        proto_block,
                        block_context,
                    })
            }
            ProtocolOutcome::FinalizedBlock(CpFinalizedBlock {
                value,
                timestamp,
                height,
                terminal_block_data,
                equivocators,
                proposer,
            }) => {
                let era = self.era_supervisor.active_eras.get_mut(&era_id).unwrap();
                era.add_accusations(&equivocators);
                era.add_accusations(value.accusations());
                // If this is the era's last block, it contains rewards. Everyone who is accused in
                // the block or seen as equivocating via the consensus protocol gets slashed.
                let era_end = terminal_block_data.map(|tbd| EraReport {
                    rewards: tbd.rewards,
                    // TODO: In the first 90 days we don't slash, and we just report all
                    // equivocators as "inactive" instead. Change this back 90 days after launch,
                    // and put era.accusations() into equivocators instead of inactive_validators.
                    equivocators: vec![],
                    inactive_validators: tbd
                        .inactive_validators
                        .into_iter()
                        .chain(era.accusations())
                        .collect(),
                });
                let finalized_block = FinalizedBlock::new(
                    value.into(),
                    timestamp,
                    era_end,
                    era_id,
                    era.start_height + height,
                    proposer,
                );
                self.era_supervisor
                    .metrics
                    .finalized_block(&finalized_block);
                // Announce the finalized proto block.
                let mut effects = self
                    .effect_builder
                    .announce_finalized_block(finalized_block.clone())
                    .ignore();
                self.era_supervisor.next_block_height = finalized_block.height() + 1;
                if finalized_block.era_report().is_some() {
                    // This was the era's last block. Schedule deactivating this era.
                    let delay = Timestamp::now().saturating_diff(timestamp).into();
                    let faulty_num = era.consensus.validators_with_evidence().len();
                    let deactivate_era = move |_| Event::DeactivateEra {
                        era_id,
                        faulty_num,
                        delay,
                    };
                    effects.extend(self.effect_builder.set_timeout(delay).event(deactivate_era));
                }
                // Request execution of the finalized block.
                effects.extend(self.effect_builder.execute_block(finalized_block).ignore());
                self.era_supervisor.update_consensus_pause();
                effects
            }
            ProtocolOutcome::ValidateConsensusValue(sender, candidate_block, timestamp) => {
                if !self.era_supervisor.is_bonded(era_id) {
                    return Effects::new();
                }
                let proto_block = candidate_block.proto_block().clone();
                let missing_evidence: Vec<PublicKey> = candidate_block
                    .accusations()
                    .iter()
                    .filter(|pub_key| !self.has_evidence(era_id, **pub_key))
                    .cloned()
                    .collect();
                let mut effects = Effects::new();
                for pub_key in missing_evidence.iter().cloned() {
                    let msg = ConsensusMessage::EvidenceRequest { era_id, pub_key };
                    effects.extend(
                        self.effect_builder
                            .send_message(sender.clone(), msg.into())
                            .ignore(),
                    );
                }
                self.era_mut(era_id)
                    .add_candidate(candidate_block, missing_evidence);
                effects.extend(
                    self.effect_builder
                        .validate_block(sender.clone(), proto_block, timestamp)
                        .event(move |(valid, proto_block)| Event::ResolveValidity {
                            era_id,
                            sender,
                            proto_block,
                            timestamp,
                            valid,
                        }),
                );
                effects
            }
            ProtocolOutcome::NewEvidence(pub_key) => {
                info!(%pub_key, era = era_id.0, "validator equivocated");
                let mut effects = self
                    .effect_builder
                    .announce_fault_event(era_id, pub_key, Timestamp::now())
                    .ignore();
                for e_id in (era_id.0..=(era_id.0 + self.era_supervisor.bonded_eras())).map(EraId) {
                    let candidate_blocks =
                        if let Some(era) = self.era_supervisor.active_eras.get_mut(&e_id) {
                            era.resolve_evidence(&pub_key)
                        } else {
                            continue;
                        };
                    for candidate_block in candidate_blocks {
                        effects.extend(self.delegate_to_era(e_id, |consensus| {
                            consensus.resolve_validity(&candidate_block, true)
                        }));
                    }
                }
                effects
            }
            ProtocolOutcome::SendEvidence(sender, pub_key) => self
                .era_supervisor
                .iter_past_other(era_id, self.era_supervisor.bonded_eras())
                .flat_map(|e_id| {
                    self.delegate_to_era(e_id, |consensus| {
                        consensus.request_evidence(sender.clone(), &pub_key)
                    })
                })
                .collect(),
            ProtocolOutcome::WeAreFaulty => Default::default(),
            ProtocolOutcome::DoppelgangerDetected => Default::default(),
            ProtocolOutcome::FttExceeded => {
                let eb = self.effect_builder;
                eb.set_timeout(Duration::from_millis(FTT_EXCEEDED_SHUTDOWN_DELAY_MILLIS))
                    .then(move |_| fatal!(eb, "too many faulty validators"))
                    .ignore()
            }
        }
    }

    /// Emits a fatal error if the consensus state is still empty.
    pub(super) fn shutdown_if_necessary(&self) -> Effects<Event<I>> {
        let should_emit_error = self
            .era_supervisor
            .active_eras
            .iter()
            .all(|(_, era)| !era.consensus.has_received_messages());
        if should_emit_error {
            fatal!(
                self.effect_builder,
                "Consensus shutting down due to inability to participate in the network; \
                inactive era = {}",
                self.era_supervisor.current_era
            )
            .ignore()
        } else {
            Default::default()
        }
    }

    pub(crate) fn finished_joining(
        &mut self,
        now: Timestamp,
        maybe_header: Option<Box<BlockHeader>>,
    ) -> Effects<Event<I>> {
        let outcomes = self.era_supervisor.finished_joining(now, maybe_header);
        self.handle_consensus_outcomes(self.era_supervisor.current_era, outcomes)
    }

    /// Handles registering an upgrade activation point.
    pub(super) fn got_upgrade_activation_point(
        &mut self,
        activation_point: ActivationPoint,
    ) -> Effects<Event<I>> {
        debug!("got {}", activation_point);
        self.era_supervisor.next_upgrade_activation_point = Some(activation_point);
        Effects::new()
    }

    /// Returns whether validator is bonded in an era.
    pub(super) fn is_bonded_validator(
        &self,
        era_id: EraId,
        vid: PublicKey,
        responder: Responder<bool>,
    ) -> Effects<Event<I>> {
        let is_bonded = self
            .era_supervisor
            .active_eras
            .get(&era_id)
            .map_or(false, |cp| cp.is_bonded_validator(&vid));
        responder.respond(is_bonded).ignore()
    }

    pub(super) fn status(
        &self,
        responder: Responder<(PublicKey, Option<TimeDiff>)>,
    ) -> Effects<Event<I>> {
        let public_key = self.era_supervisor.public_signing_key;
        let round_length = self
            .era_supervisor
            .active_eras
            .get(&self.era_supervisor.current_era)
            .and_then(|era| era.consensus.next_round_length());
        responder.respond((public_key, round_length)).ignore()
    }

    fn disconnect(&self, sender: I) -> Effects<Event<I>> {
        self.effect_builder
            .announce_disconnect_from_peer(sender)
            .ignore()
    }

    pub(super) fn should_upgrade_after(&self, era_id: &EraId) -> bool {
        match self.era_supervisor.next_upgrade_activation_point {
            None => false,
            Some(upgrade_point) => upgrade_point.should_upgrade(&era_id),
        }
    }
}

/// Computes the instance ID for an era, given the era ID and the chainspec hash.
fn instance_id(protocol_config: &ProtocolConfig, era_id: EraId) -> Digest {
    let mut result = [0; Digest::LENGTH];
    let mut hasher = VarBlake2b::new(Digest::LENGTH).expect("should create hasher");

    hasher.update(protocol_config.chainspec_hash.as_ref());
    hasher.update(era_id.0.to_le_bytes());

    hasher.finalize_variable(|slice| {
        result.copy_from_slice(slice);
    });
    result.into()
}

/// The number of past eras whose validators are still bonded. After this many eras, a former
/// validator is allowed to withdraw their stake, so their signature can't be trusted anymore.
///
/// A node keeps `2 * bonded_eras` past eras around, because the oldest bonded era could still
/// receive blocks that refer to `bonded_eras` before that.
fn bonded_eras(protocol_config: &ProtocolConfig) -> u64 {
    protocol_config.unbonding_delay - protocol_config.auction_delay
}

/// The oldest era whose validators are still bonded.
// This is public because it's used in reactor::validator::tests.
pub(crate) fn oldest_bonded_era(protocol_config: &ProtocolConfig, current_era: EraId) -> EraId {
    current_era
        .saturating_sub(bonded_eras(protocol_config))
        .max(protocol_config.last_activation_point)
}
