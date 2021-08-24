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

use crate::{mock::*, Error, PoolBalance};
use frame_support::{assert_noop, assert_ok};
use manta_asset::*;

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
