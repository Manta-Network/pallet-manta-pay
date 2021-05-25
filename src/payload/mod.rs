// Copyright 2019-2021 Manta Network.
// This file is part of pallet-manta-pay.
//
// pallet-manta-pay is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// pallet-manta-pay is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with pallet-manta-pay.  If not, see <http://www.gnu.org/licenses/>.

use crate::*;
use ark_groth16::create_random_proof;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{CryptoRng, RngCore};
use frame_support::codec::{Decode, Encode};
use manta_asset::*;
use manta_crypto::*;
use manta_error::MantaError;

mod default;
mod santiy;
mod serdes;

/// Input data to a mint extrinsic.
#[derive(Encode, Debug, Decode, Clone, Default, PartialEq)]
pub struct MintData {
	pub asset_id: AssetId,
	pub amount: u64,
	pub cm: [u8; 32],
	pub k: [u8; 32],
	pub s: [u8; 32],
}

/// Input data to a private transfer extrinsic.
#[derive(Encode, Debug, Decode, Clone, PartialEq)]
pub struct PrivateTransferData {
	pub sender_1: SenderData,
	pub sender_2: SenderData,
	pub receiver_1: ReceiverData,
	pub receiver_2: ReceiverData,
	pub proof: [u8; 192],
}

/// Input data to a reclaim extrinsic.
#[derive(Encode, Debug, Decode, Clone, PartialEq)]
pub struct ReclaimData {
	pub asset_id: AssetId,
	pub reclaim_amount: u64,
	pub sender_1: SenderData,
	pub sender_2: SenderData,
	pub receiver: ReceiverData,
	pub proof: [u8; 192],
}

/// Data required for a sender to spend a coin.
#[derive(Encode, Debug, Decode, Clone, Default, PartialEq)]
pub struct SenderData {
	pub k: [u8; 32],
	pub void_number: [u8; 32],
	pub root: [u8; 32],
}

/// Data required for a receiver to receive a coin.
#[derive(Encode, Debug, Decode, Clone, Default, PartialEq)]
pub struct ReceiverData {
	pub k: [u8; 32],
	pub cm: [u8; 32],
	pub sender_pk: [u8; 32],
	pub cipher: [u8; 16],
}

/// Given the inputs, generate the payload for the mint_asset extrinsic.
pub fn generate_mint_payload(asset: &MantaAsset) -> Result<[u8; MINT_PAYLOAD_SIZE], MantaError> {
	let data = generate_mint_struct(asset);
	let mut res = [0u8; MINT_PAYLOAD_SIZE];
	data.serialize(res.as_mut())?;
	Ok(res)
}

/// Given the inputs, generate the stuct that can be passed to
/// the mint_asset extrinsic once serialized
fn generate_mint_struct(asset: &MantaAsset) -> MintData {
	MintData {
		asset_id: asset.asset_id,
		amount: asset.priv_info.value,
		cm: asset.commitment,
		k: asset.pub_info.k,
		s: asset.pub_info.s,
	}
}

/// Given the inputs, generate the payload for the private_transfer
/// extrinsic.
/// Inputs:
///     - commit_param: commitment parameters.
///     - hash_param: hash parameters.
///     - pk: proving key of the Groth16 proving system.
///     - sender_1: meta data for the sender's first coin.
///     - sender_2: meta data for the second's first coin.
///     - receiver_1: a __PROCESSED__ receiver.
///     - receiver_2: the other __PROCESSED__ receiver.
///     - rng: a random number generator.
/// Outputs:
///     - the serialized payload that can be passed to the
///       private_transfer extrinsic.
#[allow(clippy::too_many_arguments)]
pub fn generate_private_transfer_payload<R: RngCore + CryptoRng>(
	commit_param: CommitmentParam,
	hash_param: HashParam,
	pk: &Groth16Pk,
	sender_1: SenderMetaData,
	sender_2: SenderMetaData,
	receiver_1: MantaAssetProcessedReceiver,
	receiver_2: MantaAssetProcessedReceiver,
	rng: &mut R,
) -> Result<[u8; PRIVATE_TRANSFER_PAYLOAD_SIZE], MantaError> {
	let data = generate_private_transfer_struct(
		commit_param,
		hash_param,
		pk,
		sender_1,
		sender_2,
		receiver_1,
		receiver_2,
		rng,
	)?;
	let mut res = [0u8; PRIVATE_TRANSFER_PAYLOAD_SIZE];
	data.serialize(res.as_mut())?;
	Ok(res)
}

/// Given the inputs, generate the payload for the private_transfer
/// extrinsic.
/// Inputs:
///     - commit_param: commitment parameters.
///     - hash_param: hash parameters.
///     - pk: proving key of the Groth16 proving system.
///     - sender_1: meta data for the sender's first coin.
///     - sender_2: meta data for the second's first coin.
///     - receiver_1: a __PROCESSED__ receiver.
///     - receiver_2: the other __PROCESSED__ receiver.
///     - rng: a random number generator.
/// Outputs:
///     - a data struct, once serialized, can be passed to the
///       private_transfer extrinsic.
#[allow(clippy::too_many_arguments)]
fn generate_private_transfer_struct<R: RngCore + CryptoRng>(
	commit_param: CommitmentParam,
	hash_param: HashParam,
	pk: &Groth16Pk,
	sender_1: SenderMetaData,
	sender_2: SenderMetaData,
	receiver_1: MantaAssetProcessedReceiver,
	receiver_2: MantaAssetProcessedReceiver,
	rng: &mut R,
) -> Result<PrivateTransferData, MantaError> {
	// generate circuit
	let circuit = TransferCircuit {
		commit_param,
		hash_param,

		sender_1: sender_1.clone(),
		sender_2: sender_2.clone(),

		receiver_1: receiver_1.clone(),
		receiver_2: receiver_2.clone(),
	};

	// generate ZKP
	let proof = create_random_proof(circuit, &pk, rng)?;
	let mut proof_bytes = [0u8; 192];
	proof.serialize(proof_bytes.as_mut())?;

	// serialize the roots
	let mut root_1 = [0u8; 32];
	sender_1.root.serialize(root_1.as_mut())?;

	let mut root_2 = [0u8; 32];
	sender_2.root.serialize(root_2.as_mut())?;

	Ok(PrivateTransferData {
		sender_1: SenderData {
			k: sender_1.asset.pub_info.k,
			void_number: sender_1.asset.void_number,
			root: root_1,
		},
		sender_2: SenderData {
			k: sender_2.asset.pub_info.k,
			void_number: sender_2.asset.void_number,
			root: root_2,
		},
		receiver_1: ReceiverData {
			k: receiver_1.prepared_data.k,
			cm: receiver_1.commitment,
			sender_pk: receiver_1.sender_pk,
			cipher: receiver_1.ciphertext,
		},
		receiver_2: ReceiverData {
			k: receiver_2.prepared_data.k,
			cm: receiver_2.commitment,
			sender_pk: receiver_2.sender_pk,
			cipher: receiver_2.ciphertext,
		},
		proof: proof_bytes,
	})
}

/// Given the inputs, generate the payload for the reclaim extrinsic.
/// Inputs:
///     - commit_param: commitment parameters.
///     - hash_param: hash parameters.
///     - pk: proving key of the Groth16 proving system.
///     - sender_1: meta data for the sender's first coin.
///     - sender_2: meta data for the second's first coin.
///     - receiver: a __PROCESSED__ receiver.
///     - reclaimed_value: the number of reclaimed assets.
///     - rng: a random number generator.
/// Outputs:
///     - the serialized payload that can be passed to the
///       reclaim extrinsic.
#[allow(clippy::too_many_arguments)]
pub fn generate_reclaim_payload<R: RngCore + CryptoRng>(
	commit_param: CommitmentParam,
	hash_param: HashParam,
	pk: &Groth16Pk,
	sender_1: SenderMetaData,
	sender_2: SenderMetaData,
	receiver: MantaAssetProcessedReceiver,
	reclaim_value: u64,
	rng: &mut R,
) -> Result<[u8; RECLAIM_PAYLOAD_SIZE], MantaError> {
	let data = generate_reclaim_struct(
		commit_param,
		hash_param,
		pk,
		sender_1,
		sender_2,
		receiver,
		reclaim_value,
		rng,
	)?;
	let mut res = [0u8; RECLAIM_PAYLOAD_SIZE];
	data.serialize(res.as_mut())?;
	Ok(res)
}

/// Given the inputs, generate the payload for the reclaim extrinsic.
/// Inputs:
///     - commit_param: commitment parameters.
///     - hash_param: hash parameters.
///     - pk: proving key of the Groth16 proving system.
///     - sender_1: meta data for the sender's first coin.
///     - sender_2: meta data for the second's first coin.
///     - receiver: a __PROCESSED__ receiver.
///     - reclaimed_value: the number of reclaimed assets.
///     - rng: a random number generator.
/// Outputs:
///     - a data struct, once serialized, can be passed to the
///       reclaim extrinsic.
#[allow(clippy::too_many_arguments)]
fn generate_reclaim_struct<R: RngCore + CryptoRng>(
	commit_param: CommitmentParam,
	hash_param: HashParam,
	pk: &Groth16Pk,
	sender_1: SenderMetaData,
	sender_2: SenderMetaData,
	receiver: MantaAssetProcessedReceiver,
	reclaim_value: u64,
	rng: &mut R,
) -> Result<ReclaimData, MantaError> {
	// check the asset_ids match
	// TODO: raise an `asset_id_not_match` error
	assert_eq!(
		sender_1.asset.asset_id, sender_2.asset.asset_id,
		"Asset_ids do not match"
	);
	assert_eq!(
		sender_1.asset.asset_id, receiver.prepared_data.asset_id,
		"Asset_ids do not match"
	);

	// generate circuit
	let circuit = ReclaimCircuit {
		commit_param,
		hash_param,

		sender_1: sender_1.clone(),
		sender_2: sender_2.clone(),

		receiver: receiver.clone(),

		asset_id: sender_1.asset.asset_id,
		reclaim_value,
	};

	// generate ZKP
	let proof = create_random_proof(circuit, &pk, rng)?;
	let mut proof_bytes = [0u8; 192];
	proof.serialize(proof_bytes.as_mut())?;

	// serialize the roots
	let mut root_1 = [0u8; 32];
	sender_1.root.serialize(root_1.as_mut())?;

	let mut root_2 = [0u8; 32];
	sender_2.root.serialize(root_2.as_mut())?;

	Ok(ReclaimData {
		asset_id: sender_1.asset.asset_id,
		reclaim_amount: reclaim_value,
		sender_1: SenderData {
			k: sender_1.asset.pub_info.k,
			void_number: sender_1.asset.void_number,
			root: root_1,
		},
		sender_2: SenderData {
			k: sender_2.asset.pub_info.k,
			void_number: sender_2.asset.void_number,
			root: root_2,
		},
		receiver: ReceiverData {
			k: receiver.prepared_data.k,
			cm: receiver.commitment,
			sender_pk: receiver.sender_pk,
			cipher: receiver.ciphertext,
		},
		proof: proof_bytes,
	})
}
