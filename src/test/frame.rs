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

use crate::{*, mock::*, Error, PoolBalance, VoidNumbers};
use frame_support::{assert_noop, assert_ok};
use manta_data::MintData;
use manta_crypto::commitment_parameters;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use manta_api::generate_mint_struct;
use manta_asset::{MantaAsset, TEST_ASSET, Sampling};

fn generate_mint_payload_helper(value: AssetBalance) -> MintData {
	let commit_param = commitment_parameters();
	let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
	let mut sk = [0u8; 32];
	rng.fill_bytes(&mut sk);
	let asset = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &value).unwrap();
	generate_mint_struct(&asset)
}

// todo: write must-fail tests for cross-asset-id tests
// Misc tests:
#[test]
fn issuing_asset_units_to_issuer_should_work() {
	new_test_ext().execute_with(|| {
		initialize_test(100);
	});
}

#[test]
fn querying_total_supply_should_work() {
	new_test_ext().execute_with(|| {
		initialize_test(100);
		assert_eq!(MantaPayPallet::total_supply(TEST_ASSET), 100);
	});
}
#[ignore]
#[test]
fn destroying_asset_balance_with_positive_balance_should_work() {
	unimplemented!();
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

fn initialize_test(amount: AssetBalance) {
	assert_ok!(MantaPayPallet::init_asset(
		Origin::signed(1),
		TEST_ASSET,
		amount
	));
	assert_eq!(MantaPayPallet::balance(1, TEST_ASSET), amount);
	assert_eq!(PoolBalance::<Test>::get(TEST_ASSET), 0);
}

// Mint tests:

#[test]
fn test_mint_should_work() {
	new_test_ext().execute_with(|| {
		initialize_test(1000);

		let commit_param = commitment_parameters();
		let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
		let mut sk = [0u8; 32];
		rng.fill_bytes(&mut sk);
		let asset = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &10).unwrap();

		let payload = generate_mint_struct(&asset);
		assert_ok!(MantaPayPallet::mint_private_asset(Origin::signed(1), payload));

		assert_eq!(MantaPayPallet::total_supply(TEST_ASSET), 1000);
		assert_eq!(PoolBalance::<Test>::get(TEST_ASSET), 10);
		assert!(MantaPayPallet::utxo_exists(asset.utxo));
		assert_eq!(VoidNumbers::<Test>::iter_values().count(), 0);
	});
}

#[test]
fn mint_without_init_should_not_work() {
	new_test_ext().execute_with(|| {
		let payload = generate_mint_payload_helper(100);

		assert_noop!(
			MantaPayPallet::mint_private_asset(Origin::signed(1), payload),
			Error::<Test>::BasecoinNotInit
		);
	});
}
