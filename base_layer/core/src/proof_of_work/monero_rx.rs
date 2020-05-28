// Copyright 2019. The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crate::{
    blocks::BlockHeader,
    proof_of_work::{monero_rx::MergeMineError::HashingError, Difficulty},
    U256,
};
use bincode::deserialize;
use bitflags::_core::ptr::hash;
use blake2::Digest;
use bytes::Buf;
use derive_error::Error;
use monero::{
    blockdata::{
        block::BlockHeader as MoneroBlockHeader,
        transaction::{ExtraField, SubField},
        Transaction as MoneroTransaction,
    },
    consensus::encode::VarInt,
    cryptonote::hash::*,
    Transaction,
};
#[cfg(feature = "monero_merge_mining")]
use randomx_rs::{RandomXCache, RandomXDataset, RandomXError, RandomXFlag, RandomXVM};
use serde::{Deserialize, Serialize};
use std::{hash::Hasher, str};
use tari_mmr::{common::node_index, ArrayLike, MerkleMountainRange, MerkleProof, MerkleProofError};

const MAX_TARGET: U256 = U256::MAX;

#[derive(Debug, Error, Clone)]
enum MergeMineError {
    // Error deserializing Monero data
    DeserializeError,
    // Error serializing Monero data
    SerializeError,
    // Hashing of Monero data failed
    HashingError,
    // Validation Failure
    ValidationError,
    // RandomX Failure
    #[cfg(feature = "monero_merge_mining")]
    RandomXError(RandomXError),
}

/// This is a struct to deserialize the data from he pow field into data required for the randomX Monero merged mine
/// pow.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct MoneroData {
    // Monero header fields
    // #[serde(with = "HashMoneroHeader")]
    header: MoneroBlockHeader,
    // randomX vm key
    key: String,
    // transaction count
    count: u16,
    // transaction root
    transaction_root: [u8; 32],
    // Transaction proof of work.
    merkle_proof: MerkleProof,
    // Coinbase tx from Monero
    coinbase_tx: MoneroTransaction,
}

impl MoneroData {
    fn new(tari_header: &BlockHeader) -> Result<MoneroData, MergeMineError> {
        bincode::deserialize(&tari_header.pow.pow_data).map_err(|_| MergeMineError::DeserializeError)
    }
}

/// Calculate the difficulty attained for the given block deserialized the Monero header from the provided header
pub fn monero_difficulty(header: &BlockHeader) -> Difficulty {
    match monero_difficulty_calculation(header) {
        Ok(v) => v,
        Err(_) => 0.into(), // todo this needs to change to 0 when merge mine is implemented
    }
}

/// Internal function to calculate the difficulty attained for the given block Deserialized the Monero header from the
/// provided header
fn monero_difficulty_calculation(header: &BlockHeader) -> Result<Difficulty, MergeMineError> {
    #[cfg(feature = "monero_merge_mining")]
    {
        let monero = MoneroData::new(header)?;
        verify_header(&header, &monero)?;
        let flags = RandomXFlag::get_recommended_flags();
        let key = monero.key.clone();
        let input = create_input_blob(&monero)?;
        let cache = RandomXCache::new(flags, &key)?;
        let dataset = RandomXDataset::new(flags, &cache, 0)?;
        let vm = RandomXVM::new(flags, Some(&cache), Some(&dataset))?;
        let hash = vm.calculate_hash(&input)?;
        let scalar = U256::from_big_endian(&hash); // Big endian so the hash has leading zeroes
        let result = MAX_TARGET / scalar;
        let difficulty = result.low_u64().into();
        Ok(difficulty)
    }
    #[cfg(not(feature = "monero_merge_mining"))]
    {
        Err(MergeMineError::HashingError)
    }
}

fn create_input_blob(data: &MoneroData) -> Result<String, MergeMineError> {
    let serialized_header = bincode::serialize(&data.header);
    if !serialized_header.is_ok() {
        return Err(MergeMineError::SerializeError);
    }
    let serialized_root_hash = bincode::serialize(&data.transaction_root);
    if !serialized_root_hash.is_ok() {
        return Err(MergeMineError::SerializeError);
    }
    let serialized_transaction_count = bincode::serialize(&data.count);
    if !serialized_transaction_count.is_ok() {
        return Err(MergeMineError::SerializeError);
    }

    let mut pre_hash_blob = serialized_header.unwrap();
    pre_hash_blob.append(&mut serialized_root_hash.unwrap());
    pre_hash_blob.append(&mut serialized_transaction_count.unwrap());
    let hash_blob = Hash::hash(pre_hash_blob.as_slice());
    let hash_vec = hash_blob.0.clone().to_vec();
    let hash_result = str::from_utf8(hash_vec.as_slice());
    if !hash_result.is_ok() {
        return Err(MergeMineError::HashingError);
    }
    Ok(hash_result.unwrap().into())
}

fn verify_header(header: &BlockHeader, monero_data: &MoneroData) -> Result<(), MergeMineError> {
    if !(monero_data.coinbase_tx.prefix.extra.0.contains(&SubField::MergeMining(
        VarInt(header.height),
        Hash::hash(header.kernel_mr.as_slice()),
    ))) {
        return Err(MergeMineError::ValidationError);
    }

    Ok(())
}
