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
use ark_std::rand::Rng;
use frame_support::{assert_noop, assert_ok};
use manta_api::{
	generate_mint_struct, generate_private_transfer_struct,
	zkp::{keys::write_zkp_keys, sample::*},
};
use manta_asset::TEST_ASSET;
use manta_crypto::{
	commitment_parameters, leaf_parameters, two_to_one_parameters, CommitmentParam, Groth16Pk,
	LeafHashParam, TwoToOneHashParam,
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::{fs::File, io::Read, sync::Once};

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
fn params_for_reclaim() -> Groth16Pk {
	load_zkp_key("reclaim_pk.bin")
}

/// Mint manta assets with specified asset_id and balances to an empty pool
fn mint_tokens_to_empty_pool(
	asset_id: &AssetId,
	balances: &Vec<AssetBalance>,
	rng: &mut ChaCha20Rng,
) {
	// make sure the pool is empty from start
	let mut pool = 0;
	assert_eq!(PoolBalance::<Test>::get(asset_id), pool);

	for token_value in balances {
		// build and mint token
		let asset = fixed_asset(&COMMIT_PARAMS, asset_id, token_value, rng);
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

/// Perform `transfer_count` times random private transfer
fn transfer_test(transfer_count: usize, rng: &mut ChaCha20Rng) {
	// generate asset_id and transfer balances
	let asset_id = rng.gen();
	let total_balance: AssetBalance = rng.gen();
	let balances: Vec<AssetBalance> = value_distribution(transfer_count, total_balance, rng);
	initialize_test(&asset_id, &total_balance);

	let mut utxo_set = Vec::new();
	let transfer_pk = transfer_pk();
	for balance in balances {
		let (senders, receivers) = fixed_transfer(
			&LEAF_PARAMS,
			&TWO_TO_ONE_PARAMS,
			&COMMIT_PARAMS,
			&asset_id,
			&balance,
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
			senders,
			receivers,
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
		assert_eq!(PoolBalance::<Test>::get(asset_id), total_balance);
		for receiver in receivers {
			assert!(MantaPayPallet::utxo_exists(receiver.utxo));
		}
	}
}

// Init tests:
#[test]
fn cannot_init_twice() {
	new_test_ext().execute_with(|| {
		assert_ok!(MantaPayPallet::init_asset(
			Origin::signed(1),
			TEST_ASSET,
			100
		));
		assert_noop!(
			MantaPayPallet::init_asset(Origin::signed(1), TEST_ASSET, 100),
			Error::<Test>::AlreadyInitialized
		);
	});
}

fn initialize_test(asset_id: &AssetId, amount: &AssetBalance) {
	assert_ok!(MantaPayPallet::init_asset(
		Origin::signed(1),
		*asset_id,
		*amount
	));
	assert_eq!(MantaPayPallet::balance(1, *asset_id), *amount);
	assert_eq!(PoolBalance::<Test>::get(*asset_id), 0);
}

// Mint tests:

#[test]
fn test_mint_should_work() {
	new_test_ext().execute_with(|| {
		let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
		let asset_id = rng.gen();
		let total_supply = 1000;
		initialize_test(&asset_id, &total_supply);
		let balances = value_distribution(5, total_supply, &mut rng);
		mint_tokens_to_empty_pool(&asset_id, &balances, &mut rng);
	});
}

#[test]
fn over_mint_should_not_work() {
	let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
	let asset_id = rng.gen();
	let total_supply = 32579;
	initialize_test(&asset_id, &total_supply);
	let asset = fixed_asset(&COMMIT_PARAMS, &asset_id, &32580, &mut rng);
	let mint_data = generate_mint_struct(&asset);
	assert_noop!(
		MantaPayPallet::mint_private_asset(Origin::signed(1), mint_data),
		Error::<Test>::MintFail
	);
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
fn test_transfer_should_work() {
	let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
	new_test_ext().execute_with(|| transfer_test(1, &mut rng));
}
