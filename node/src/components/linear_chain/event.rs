use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
};

use crate::{
    effect::{requests::LinearChainRequest, Responder},
    types::{Block, BlockHash, BlockSignatures, DeployHash, FinalitySignature},
};
use casper_types::ExecutionResult;

use derive_more::From;

impl<I> From<Box<FinalitySignature>> for Event<I> {
    fn from(fs: Box<FinalitySignature>) -> Self {
        Event::FinalitySignatureReceived(fs)
    }
}

#[derive(Debug, From)]
pub enum Event<I> {
    /// A linear chain request issued by another node in the network.
    #[from]
    Request(LinearChainRequest<I>),
    /// New linear chain block has been produced.
    LinearChainBlock {
        /// The block.
        block: Box<Block>,
        /// The deploys' execution results.
        execution_results: HashMap<DeployHash, ExecutionResult>,
    },
    /// A continuation for `GetBlock` scenario.
    GetBlockResult(BlockHash, Option<Box<Block>>, I),
    /// A continuation for `BlockAtHeight` scenario.
    GetBlockByHeightResult(u64, Option<Box<Block>>, I),
    /// A continuation for `BlockAtHeightLocal` scenario.
    GetBlockByHeightResultLocal(u64, Option<Box<Block>>, Responder<Option<Block>>),
    /// Finality signature received.
    /// Not necessarily _new_ finality signature.
    FinalitySignatureReceived(Box<FinalitySignature>),
    /// The result of putting a block to storage.
    PutBlockResult {
        /// The block.
        block: Box<Block>,
        /// The deploys' execution results.
        execution_results: HashMap<DeployHash, ExecutionResult>,
    },
    /// The result of requesting finality signatures from storage to add pending signatures.
    GetStoredFinalitySignaturesResult(Box<FinalitySignature>, Option<Box<BlockSignatures>>),
    /// Check if validator is bonded in the future era.
    /// Validator's public key and the block's era are part of the finality signature.
    IsBondedFutureEra(Option<Box<BlockSignatures>>, Box<FinalitySignature>),
    /// Result of testing if creator of the finality signature is bonded validator.
    IsBonded(Option<Box<BlockSignatures>>, Box<FinalitySignature>, bool),
}

impl<I: Display> Display for Event<I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Event::Request(req) => write!(f, "linear chain request: {}", req),
            Event::LinearChainBlock { block, .. } => {
                write!(f, "linear chain new block: {}", block.hash())
            }
            Event::GetBlockResult(block_hash, maybe_block, peer) => write!(
                f,
                "linear chain get-block for {} from {} found: {}",
                block_hash,
                peer,
                maybe_block.is_some()
            ),
            Event::FinalitySignatureReceived(fs) => write!(
                f,
                "linear-chain new finality signature for block: {}, from: {}",
                fs.block_hash, fs.public_key,
            ),
            Event::PutBlockResult { .. } => write!(f, "linear-chain put-block result"),
            Event::GetBlockByHeightResult(height, result, peer) => write!(
                f,
                "linear chain get-block-height for height {} from {} found: {}",
                height,
                peer,
                result.is_some()
            ),
            Event::GetBlockByHeightResultLocal(height, block, _) => write!(
                f,
                "linear chain get-block-height-local for height={} found={}",
                height,
                block.is_some()
            ),
            Event::GetStoredFinalitySignaturesResult(finality_signature, maybe_signatures) => {
                write!(
                    f,
                    "linear chain get-stored-finality-signatures result for {} found: {}",
                    finality_signature.block_hash,
                    maybe_signatures.is_some(),
                )
            }
            Event::IsBonded(_block, fs, is_bonded) => {
                write!(
                    f,
                    "linear chain is-bonded for era {} validator {}, is_bonded: {}",
                    fs.era_id, fs.public_key, is_bonded
                )
            }
            Event::IsBondedFutureEra(_block, fs) => {
                write!(
                    f,
                    "linear chain is-bonded for future era {} validator {}",
                    fs.era_id, fs.public_key
                )
            }
        }
    }
}
