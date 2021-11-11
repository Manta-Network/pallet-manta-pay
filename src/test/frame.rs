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

use crate::{mock::*, Error, LedgerShardMetaData, LedgerShards, PoolBalance, VoidNumbers, *};
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::{Rng, RngCore};
use core::convert::TryInto;
use frame_support::{assert_noop, assert_ok};
use manta_api::{
	generate_mint_struct, generate_private_transfer_struct, generate_reclaim_struct,
	zkp::{keys::write_zkp_keys, sample::*},
};
use manta_asset::{MantaAsset, MantaAssetProcessedReceiver, NUM_BYTE_ZKP};
use manta_crypto::{
	commitment_parameters, leaf_parameters, two_to_one_parameters, CommitmentParam, Groth16Pk,
	LeafHashParam, MantaSerDes, Parameter, TwoToOneHashParam,
};
use manta_data::{BuildMetadata, SenderMetaData};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::{collections::HashMap, fs::File, io::Read, sync::Once};

lazy_static::lazy_static! {
	static ref COMMIT_PARAMS: CommitmentParam = commitment_parameters();
	static ref LEAF_PARAMS: LeafHashParam = leaf_parameters();
	static ref TWO_TO_ONE_PARAMS: TwoToOneHashParam = two_to_one_parameters();
}

static INIT: Once = Once::new();
fn manta_zkp_key_generation() {
	INIT.call_once(|| write_zkp_keys().unwrap());
}

/// load precomputed zkp key from storage
/// filename can only be "transfer_pk.bin" or "reclaim_pk.bin"
fn load_zkp_key(file_name: &str) -> Groth16Pk {
	assert!(file_name == "transfer_pk.bin" || file_name == "reclaim_pk.bin");
	manta_zkp_key_generation();

	let mut file = File::open(file_name).unwrap();
	let mut transfer_key_bytes: Vec<u8> = vec![];
	file.read_to_end(&mut transfer_key_bytes).unwrap();
	let buf: &[u8] = transfer_key_bytes.as_ref();
	Groth16Pk::deserialize_unchecked(buf).unwrap()
}

/// Return proving key for transfer
fn transfer_pk() -> Groth16Pk {
	load_zkp_key("transfer_pk.bin")
}

/// Return proving key for reclaim
fn reclaim_pk() -> Groth16Pk {
	load_zkp_key("reclaim_pk.bin")
}

/// Mint manta assets with specified asset_id and balances to an empty pool
fn mint_tokens_to_empty_pool(asset_id: AssetId, balances: &[AssetBalance], rng: &mut ChaCha20Rng) {
	// make sure the pool is empty from start
	let mut pool = 0;
	assert_eq!(PoolBalance::<Test>::get(asset_id), pool);

	for token_value in balances {
		// build and mint token
		let asset = fixed_asset(&COMMIT_PARAMS, asset_id, *token_value, rng);
		let mint_data = generate_mint_struct(&asset);
		assert_ok!(MantaPayPallet::mint_private_asset(
			Origin::signed(1),
			mint_data
		));

		// sanity checks
		pool += token_value;
		assert_eq!(PoolBalance::<Test>::get(asset_id), pool);
		assert!(MantaPayPallet::utxo_exists(asset.utxo));
		assert_eq!(VoidNumbers::<Test>::iter_values().count(), 0);
	}
}

/// Insert utxo to the commitment set
fn insert_utxo(utxo: &UTXO, commitment_set: &mut HashMap<u8, Vec<[u8; 32]>>) {
	let shard_index = shard_index(*utxo);
	let shard = commitment_set.entry(shard_index).or_default();
	shard.push(*utxo);
}

/// We cannot just simply use `fixed_transfer` here since it would generate wrong merkle proof
#[allow(clippy::too_many_arguments)]
fn sample_fixed_sender_and_receiver(
	sender_count: usize,
	receiver_count: usize,
	leaf_params: &LeafHashParam,
	two_to_one_params: &TwoToOneHashParam,
	commit_params: &CommitmentParam,
	asset_id: AssetId,
	total_sender_balance: AssetBalance,
	total_receiver_balance: AssetBalance,
	commitment_set: &mut HashMap<u8, Vec<[u8; 32]>>,
	rng: &mut ChaCha20Rng,
) -> (Vec<SenderMetaData>, Vec<MantaAssetProcessedReceiver>) {
	let (sender_values, receiver_values) = (
		value_distribution(sender_count, total_sender_balance, rng),
		value_distribution(receiver_count, total_receiver_balance, rng),
	);

	let senders = IntoIterator::into_iter(sender_values)
		.map(|value| {
			let asset = fixed_asset(commit_params, asset_id, value, rng);
			insert_utxo(&asset.utxo, commitment_set);
			asset
				.build(
					leaf_params,
					two_to_one_params,
					commitment_set.get(&shard_index(asset.utxo)).unwrap(),
				)
				.unwrap()
		})
		.collect::<Vec<_>>();

	let receivers = IntoIterator::into_iter(receiver_values)
		.map(|value| fixed_receiver(commit_params, asset_id, value, rng))
		.collect::<Vec<_>>();
	(senders, receivers)
}

/// Copied from manta_api::util, maybe we should make this function public in manta_api?
fn into_array_unchecked<V, T, const N: usize>(v: V) -> [T; N]
where
	V: TryInto<[T; N]>,
{
	match v.try_into() {
		Ok(array) => array,
		_ => unreachable!(),
	}
}

/// flip a random bit in the proof
fn random_bit_flip_in_zkp(proof: &mut [u8; NUM_BYTE_ZKP], rng: &mut ChaCha20Rng) {
	let byte_to_flip = rng.gen_range(0..NUM_BYTE_ZKP);
	let masks = [
		0b1000_0000,
		0b0100_0000,
		0b0010_0000,
		0b0001_0000,
		0b0000_1000,
		0b0000_0100,
		0b0000_0010,
		0b0000_0001,
	];
	let bit_to_flip = rng.gen_range(0..8);
	proof[byte_to_flip] ^= masks[bit_to_flip];
}

/// Perform `transfer_count` times random private transfer
fn transfer_test(transfer_count: usize, rng: &mut ChaCha20Rng) {
	// generate asset_id and transfer balances
	let asset_id = rng.gen();
	let total_balance: AssetBalance = rng.gen();
	let balances: Vec<AssetBalance> = value_distribution(transfer_count, total_balance, rng);
	initialize_test(asset_id, total_balance);

	let mut utxo_set = HashMap::new();
	let mut current_pool_balance = 0;
	let transfer_pk = transfer_pk();
	for balance in balances {
		let (senders, receivers) = sample_fixed_sender_and_receiver(
			2,
			2,
			&LEAF_PARAMS,
			&TWO_TO_ONE_PARAMS,
			&COMMIT_PARAMS,
			asset_id,
			balance,
			balance,
			&mut utxo_set,
			rng,
		);

		// mint private tokens
		for sender in senders.clone() {
			let mint_data = generate_mint_struct(&sender.asset);
			assert_ok!(MantaPayPallet::mint_private_asset(
				Origin::signed(1),
				mint_data
			));
		}
		// transfer private tokens
		let priv_trans_data = generate_private_transfer_struct(
			COMMIT_PARAMS.clone(),
			LEAF_PARAMS.clone(),
			TWO_TO_ONE_PARAMS.clone(),
			&transfer_pk,
			into_array_unchecked(senders),
			into_array_unchecked(receivers.clone()),
			rng,
		)
		.unwrap();
		assert_ok!(MantaPayPallet::private_transfer(
			Origin::signed(1),
			priv_trans_data
		));

		// check the utxos and ciphertexts
		let (shard_index_1, shard_index_2) = (
			shard_index(receivers[0].utxo),
			shard_index(receivers[1].utxo),
		);
		let (meta_data_1, meta_data_2) = (
			LedgerShardMetaData::<Test>::get(shard_index_1),
			LedgerShardMetaData::<Test>::get(shard_index_2),
		);
		let ledger_entries = if shard_index_1 == shard_index_2 {
			[
				LedgerShards::<Test>::get(shard_index_1, meta_data_2.current_index),
				LedgerShards::<Test>::get(shard_index_1, meta_data_1.current_index - 1),
			]
		} else {
			[
				LedgerShards::<Test>::get(shard_index_1, meta_data_2.current_index),
				LedgerShards::<Test>::get(shard_index_2, meta_data_2.current_index),
			]
		};

		// Check ledger entry written
		for (i, entry) in ledger_entries.iter().enumerate() {
			assert_eq!(entry.0, receivers[i].utxo);
			assert_eq!(entry.1, receivers[i].encrypted_note);
		}

		// TODO: check the wellformness of ciphertexts
		// Check pool balance and utxo exists
		current_pool_balance += balance;
		assert_eq!(PoolBalance::<Test>::get(asset_id), current_pool_balance);
		for receiver in receivers {
			assert!(MantaPayPallet::utxo_exists(receiver.utxo));
		}
	}
}

/// Perform `reclaim_count` times reclaim
fn reclaim_test(reclaim_count: usize, rng: &mut ChaCha20Rng) {
	let asset_id = rng.gen();
	let total_balance = rng.gen();
	let balances: Vec<AssetBalance> = value_distribution(reclaim_count, total_balance, rng);
	initialize_test(asset_id, total_balance);

	let mut utxo_set = HashMap::new();
	let mut current_pool_balance = 0;
	let reclaim_pk = reclaim_pk();
	for balance in balances {
		let reclaim_balances = value_distribution(2, balance, rng);
		let (receiver_value, reclaim_value) = (reclaim_balances[0], reclaim_balances[1]);

		let (senders, receivers) = sample_fixed_sender_and_receiver(
			2,
			1,
			&LEAF_PARAMS,
			&TWO_TO_ONE_PARAMS,
			&COMMIT_PARAMS,
			asset_id,
			balance,
			receiver_value,
			&mut utxo_set,
			rng,
		);

		// mint private tokens
		for sender in senders.clone() {
			let mint_data = generate_mint_struct(&sender.asset);
			assert_ok!(MantaPayPallet::mint_private_asset(
				Origin::signed(1),
				mint_data
			));
		}
		current_pool_balance += balance;
		assert_eq!(PoolBalance::<Test>::get(asset_id), current_pool_balance);

		let receiver = receivers[0];

		// make reclaim
		let reclaim_data = generate_reclaim_struct(
			COMMIT_PARAMS.clone(),
			LEAF_PARAMS.clone(),
			TWO_TO_ONE_PARAMS.clone(),
			&reclaim_pk,
			into_array_unchecked(senders),
			receiver,
			reclaim_value,
			rng,
		)
		.unwrap();

		assert_ok!(MantaPayPallet::reclaim(Origin::signed(1), reclaim_data));
		current_pool_balance -= reclaim_value;
		assert_eq!(PoolBalance::<Test>::get(asset_id), current_pool_balance);

		// Check ledger state has been correctly updated
		let shard_index = shard_index(receiver.utxo);
		let meta_data = LedgerShardMetaData::<Test>::get(shard_index);
		let ledger_entry = LedgerShards::<Test>::get(shard_index, meta_data.current_index);
		assert_eq!(ledger_entry.0, receiver.utxo);
		assert_eq!(ledger_entry.1, receiver.encrypted_note);
		assert!(MantaPayPallet::utxo_exists(receiver.utxo));
	}
}

// Init tests:
fn initialize_test(asset_id: AssetId, amount: AssetBalance) {
	MantaPayPallet::init_asset(&1, asset_id, amount);
	assert_eq!(MantaPayPallet::balance(1, asset_id), amount);
	assert_eq!(PoolBalance::<Test>::get(asset_id), 0);
}

// Mint tests:

#[test]
fn test_mint_should_work() {
	new_test_ext().execute_with(|| {
		let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
		let asset_id = rng.gen();
		let total_supply = 1000;
		initialize_test(asset_id, total_supply);
		let balances = value_distribution(5, total_supply, &mut rng);
		mint_tokens_to_empty_pool(asset_id, &balances, &mut rng);
	});
}

#[test]
fn over_mint_should_not_work() {
	new_test_ext().execute_with(|| {
		let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
		let asset_id = rng.gen();
		let total_supply = 32579;
		initialize_test(asset_id, total_supply);
		let asset = fixed_asset(&COMMIT_PARAMS, asset_id, 32580, &mut rng);
		let mint_data = generate_mint_struct(&asset);
		assert_noop!(
			MantaPayPallet::mint_private_asset(Origin::signed(1), mint_data),
			Error::<Test>::BalanceLow
		);
	});
}

#[test]
fn mint_without_init_should_not_work() {
	new_test_ext().execute_with(|| {
		let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
		let asset = asset(&COMMIT_PARAMS, &mut rng);
		let mint_data = generate_mint_struct(&asset);
		assert_noop!(
			MantaPayPallet::mint_private_asset(Origin::signed(1), mint_data),
			Error::<Test>::BasecoinNotInit
		);
	});
}

#[test]
fn mint_existing_coin_should_not_work() {
	new_test_ext().execute_with(|| {
		let mut rng = ChaCha20Rng::from_seed([41u8; 32]);
		let asset_id = rng.gen();
		let total_supply = 32579;
		initialize_test(asset_id, total_supply);
		let asset = fixed_asset(&COMMIT_PARAMS, asset_id, 100, &mut rng);
		let mint_data = generate_mint_struct(&asset);
		assert_ok!(MantaPayPallet::mint_private_asset(
			Origin::signed(1),
			mint_data
		));
		assert_noop!(
			MantaPayPallet::mint_private_asset(Origin::signed(1), mint_data),
			Error::<Test>::LedgerUpdateFail
		);
	});
}

#[test]
fn mint_with_invalid_commitment_should_not_work() {
	new_test_ext().execute_with(|| {
		let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
		let asset_id = rng.gen();
		initialize_test(asset_id, 100);

		let data: &[u8; 81664] = &[5u8; 81664];
		let mut raw_param = Parameter { data };
		let commit_param = CommitmentParam::deserialize(&mut raw_param.data).unwrap();
		let mut sk = [0u8; 32];
		rng.fill_bytes(&mut sk);
		let asset = MantaAsset::new(sk, &commit_param, asset_id, 50).unwrap();
		let payload = generate_mint_struct(&asset);

		assert_noop!(
			MantaPayPallet::mint_private_asset(Origin::signed(1), payload),
			Error::<Test>::MintFail
		);
	});
}

#[test]
fn test_transfer_should_work() {
	let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
	new_test_ext().execute_with(|| transfer_test(1, &mut rng));
}

#[test]
fn test_transfer_5_times_should_work() {
	let mut rng = ChaCha20Rng::from_seed([41u8; 32]);
	new_test_ext().execute_with(|| transfer_test(5, &mut rng));
}

#[test]
fn double_spend_in_transfer_shoud_not_work() {
	let mut rng = ChaCha20Rng::from_seed([37u8; 32]);
	new_test_ext().execute_with(|| {
		let asset_id = rng.gen();
		initialize_test(asset_id, 800000);

		let transfer_pk = transfer_pk();
		let mut utxo_set = HashMap::new();
		let (senders, receivers) = sample_fixed_sender_and_receiver(
			2,
			2,
			&LEAF_PARAMS,
			&TWO_TO_ONE_PARAMS,
			&COMMIT_PARAMS,
			asset_id,
			5000,
			5000,
			&mut utxo_set,
			&mut rng,
		);

		// mint private tokens
		for sender in senders.clone() {
			let mint_data = generate_mint_struct(&sender.asset);
			assert_ok!(MantaPayPallet::mint_private_asset(
				Origin::signed(1),
				mint_data
			));
		}
		// transfer private tokens
		let priv_trans_data = generate_private_transfer_struct(
			COMMIT_PARAMS.clone(),
			LEAF_PARAMS.clone(),
			TWO_TO_ONE_PARAMS.clone(),
			&transfer_pk,
			into_array_unchecked(senders),
			into_array_unchecked(receivers),
			&mut rng,
		)
		.unwrap();
		assert_ok!(MantaPayPallet::private_transfer(
			Origin::signed(1),
			priv_trans_data
		));

		// try to spend again, this time should fail
		assert_noop!(
			MantaPayPallet::private_transfer(Origin::signed(1), priv_trans_data),
			Error::<Test>::MantaCoinSpent
		);
	});
}

#[test]
fn transfer_with_invalid_zkp_should_not_work() {
	let mut rng = ChaCha20Rng::from_seed([37u8; 32]);
	new_test_ext().execute_with(|| {
		let asset_id = rng.gen();
		initialize_test(asset_id, 800000);

		let transfer_pk = transfer_pk();
		let mut utxo_set = HashMap::new();
		let (senders, receivers) = sample_fixed_sender_and_receiver(
			2,
			2,
			&LEAF_PARAMS,
			&TWO_TO_ONE_PARAMS,
			&COMMIT_PARAMS,
			asset_id,
			5000,
			5000,
			&mut utxo_set,
			&mut rng,
		);

		// mint private tokens
		for sender in senders.clone() {
			let mint_data = generate_mint_struct(&sender.asset);
			assert_ok!(MantaPayPallet::mint_private_asset(
				Origin::signed(1),
				mint_data
			));
		}
		// transfer private tokens
		let mut priv_trans_data = generate_private_transfer_struct(
			COMMIT_PARAMS.clone(),
			LEAF_PARAMS.clone(),
			TWO_TO_ONE_PARAMS.clone(),
			&transfer_pk,
			into_array_unchecked(senders),
			into_array_unchecked(receivers),
			&mut rng,
		)
		.unwrap();
		// flip a random bit in zkp
		random_bit_flip_in_zkp(&mut priv_trans_data.proof, &mut rng);
		assert_noop!(
			MantaPayPallet::private_transfer(Origin::signed(1), priv_trans_data),
			Error::<Test>::ZkpVerificationFail
		);
	});
}

#[test]
fn test_reclaim_should_work() {
	let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
	new_test_ext().execute_with(|| reclaim_test(1, &mut rng));
}

#[test]
fn test_reclaim_5_times_should_work() {
	let mut rng = ChaCha20Rng::from_seed([41u8; 32]);
	new_test_ext().execute_with(|| reclaim_test(5, &mut rng));
}

#[test]
fn double_spend_in_reclaim_should_not_work() {
	let mut rng = ChaCha20Rng::from_seed([41u8; 32]);
	new_test_ext().execute_with(|| {
		let asset_id = rng.gen();
		let total_balance = 3289172;
		let receiver_value = 12590;
		let reclaim_value = total_balance - receiver_value;
		initialize_test(asset_id, total_balance);

		let mut utxo_set = HashMap::new();
		let reclaim_pk = reclaim_pk();
		let (senders, receivers) = sample_fixed_sender_and_receiver(
			2,
			1,
			&LEAF_PARAMS,
			&TWO_TO_ONE_PARAMS,
			&COMMIT_PARAMS,
			asset_id,
			total_balance,
			receiver_value,
			&mut utxo_set,
			&mut rng,
		);

		// mint private tokens
		for sender in senders.clone() {
			let mint_data = generate_mint_struct(&sender.asset);
			assert_ok!(MantaPayPallet::mint_private_asset(
				Origin::signed(1),
				mint_data
			));
		}

		let receiver = receivers[0];

		// make reclaim
		let reclaim_data = generate_reclaim_struct(
			COMMIT_PARAMS.clone(),
			LEAF_PARAMS.clone(),
			TWO_TO_ONE_PARAMS.clone(),
			&reclaim_pk,
			into_array_unchecked(senders),
			receiver,
			reclaim_value,
			&mut rng,
		)
		.unwrap();

		assert_ok!(MantaPayPallet::reclaim(Origin::signed(1), reclaim_data));
		// double spend should fail
		assert_noop!(
			MantaPayPallet::reclaim(Origin::signed(1), reclaim_data),
			Error::<Test>::MantaCoinSpent,
		);
	});
}

#[test]
fn reclaim_with_invalid_zkp_should_not_work() {
	let mut rng = ChaCha20Rng::from_seed([55u8; 32]);
	new_test_ext().execute_with(|| {
		let asset_id = rng.gen();
		let total_balance = 3289172;
		let receiver_value = 12590;
		let reclaim_value = total_balance - receiver_value;
		initialize_test(asset_id, total_balance);

		let mut utxo_set = HashMap::new();
		let reclaim_pk = reclaim_pk();
		let (senders, receivers) = sample_fixed_sender_and_receiver(
			2,
			1,
			&LEAF_PARAMS,
			&TWO_TO_ONE_PARAMS,
			&COMMIT_PARAMS,
			asset_id,
			total_balance,
			receiver_value,
			&mut utxo_set,
			&mut rng,
		);

		// mint private tokens
		for sender in senders.clone() {
			let mint_data = generate_mint_struct(&sender.asset);
			assert_ok!(MantaPayPallet::mint_private_asset(
				Origin::signed(1),
				mint_data
			));
		}

		let receiver = receivers[0];

		// make reclaim
		let mut reclaim_data = generate_reclaim_struct(
			COMMIT_PARAMS.clone(),
			LEAF_PARAMS.clone(),
			TWO_TO_ONE_PARAMS.clone(),
			&reclaim_pk,
			into_array_unchecked(senders),
			receiver,
			reclaim_value,
			&mut rng,
		)
		.unwrap();

		// flip a random bit in zkp
		random_bit_flip_in_zkp(&mut reclaim_data.proof, &mut rng);
		assert_noop!(
			MantaPayPallet::reclaim(Origin::signed(1), reclaim_data),
			Error::<Test>::ZkpVerificationFail,
		);
	});
}
