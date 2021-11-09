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

#![cfg(feature = "runtime-benchmarks")]

mod precomputed_coins;

use super::*;

use crate::benchmark::precomputed_coins::{COIN_1, COIN_2, RECLAIM_DATA, TRANSFER_DATA};
#[allow(unused)]
use crate::Pallet as PalletMantaPay;
use frame_benchmarking::{account, benchmarks, impl_benchmark_test_suite, whitelisted_caller};
use frame_system::{EventRecord, RawOrigin};
use manta_asset::TEST_ASSET;
use manta_crypto::MantaSerDes;
use sp_runtime::traits::StaticLookup;

const SEED: u32 = 0;

pub fn assert_last_event<T: Config>(generic_event: <T as Config>::Event) {
	let events = frame_system::Pallet::<T>::events();
	let system_event: <T as frame_system::Config>::Event = generic_event.into();
	let EventRecord { event, .. } = &events[events.len() - 1];
	assert_eq!(event, &system_event);
}

benchmarks! {

	transfer_asset {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		Balances::<T>::insert(&caller, TEST_ASSET, 1_000);
		Pallet::<T>::init_asset(caller.clone(), TEST_ASSET, 1_000);
		let recipient: T::AccountId = account("recipient", 0, SEED);
		let recipient_lookup: <T::Lookup as StaticLookup>::Source = T::Lookup::unlookup(recipient.clone());
		let transfer_amount = 10;
	}: transfer_asset(
		RawOrigin::Signed(caller.clone()),
		recipient_lookup,
		TEST_ASSET,
		transfer_amount)
	verify {
		assert_last_event::<T>(
			Event::Transferred(TEST_ASSET, caller, recipient.clone(), transfer_amount).into()
		);
		assert_eq!(Balances::<T>::get(&recipient, TEST_ASSET), transfer_amount);
	}

	mint_private_asset {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, TEST_ASSET, 1_000_000);
		Pallet::<T>::init_asset(caller.clone(), TEST_ASSET, 1_000_000);
		let mut mint_bytes: Vec<u8> = Vec::new();
		mint_bytes.extend_from_slice(COIN_1);
		let mint_data = MintData::deserialize(&mut mint_bytes.as_ref()).unwrap();
	}: mint_private_asset (
		RawOrigin::Signed(caller),
		mint_data)
	verify {
		assert_eq!(TotalSupply::<T>::get(TEST_ASSET), 1_000_000);
		assert_eq!(PoolBalance::<T>::get(TEST_ASSET), 89_757);
	}

	private_transfer {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, TEST_ASSET, 1_000_000);
		Pallet::<T>::init_asset(caller.clone(), TEST_ASSET, 1_000_000);

		for coin in [COIN_1, COIN_2] {
			let mut coin_bytes: Vec<u8> = Vec::new();
			coin_bytes.extend_from_slice(coin);
			let mint_data = MintData::deserialize(&mut coin_bytes.as_ref()).unwrap();
			Pallet::<T>::mint_private_asset(origin.clone(), mint_data).unwrap();
		}

		let mut test_transfer_bytes: Vec<u8> = Vec::new();
		test_transfer_bytes.extend_from_slice(TRANSFER_DATA);
		let transfer_data = PrivateTransferData::deserialize(&mut test_transfer_bytes.as_ref()).unwrap();

	}: private_transfer (
		RawOrigin::Signed(caller.clone()),
		transfer_data)
	verify {
		assert_last_event::<T>(Event::PrivateTransferred(caller).into());
		assert_eq!(TotalSupply::<T>::get(TEST_ASSET), 1_000_000);
		assert_eq!(PoolBalance::<T>::get(TEST_ASSET), 179_515);
	}

	reclaim {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, TEST_ASSET, 1_000_000);
		Pallet::<T>::init_asset(caller.clone(), TEST_ASSET, 1_000_000);

		for coin in [COIN_1, COIN_2] {
			let mut coin_bytes: Vec<u8> = Vec::new();
			coin_bytes.extend_from_slice(coin);
			let mint_data = MintData::deserialize(&mut coin_bytes.as_ref()).unwrap();
			Pallet::<T>::mint_private_asset(origin.clone(), mint_data).unwrap();
		}

		let mut reclaim_bytes: Vec<u8> = Vec::new();
		reclaim_bytes.extend_from_slice(RECLAIM_DATA);
		let reclaim_data = ReclaimData::deserialize(&mut reclaim_bytes.as_ref()).unwrap();
	}: reclaim (
		RawOrigin::Signed(caller.clone()),
		reclaim_data
	)
	verify {
		assert_last_event::<T>(Event::Reclaimed(TEST_ASSET, caller, 79_515).into());
		assert_eq!(TotalSupply::<T>::get(TEST_ASSET), 1_000_000);
		assert_eq!(PoolBalance::<T>::get(TEST_ASSET), 100_000);
	}
}

impl_benchmark_test_suite!(
	PalletMantaPay,
	crate::mock::new_test_ext(),
	crate::mock::Test,
);
