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

//! manta-pay pallet benchmarking.
#![cfg(feature = "runtime-benchmarks")]

#[cfg(test)]
mod bench_composite;

use super::*;
use ark_std::{boxed::Box, primitive::str, vec, vec::Vec};
use frame_benchmarking::{account, benchmarks, whitelisted_caller};
use frame_system::{EventRecord, RawOrigin};
use manta_asset::TEST_ASSET;

const SEED: u32 = 0;

pub fn assert_last_event<T: Config>(generic_event: <T as Config>::Event) {
	let events = frame_system::Module::<T>::events();
	let system_event: <T as frame_system::Config>::Event = generic_event.into();
	let EventRecord { event, .. } = &events[events.len() - 1];
	assert_eq!(event, &system_event);
}

benchmarks! {

	init_asset {
		let caller: T::AccountId = whitelisted_caller();
		let total = 1000u128;
	}: init_asset (RawOrigin::Signed(caller.clone()), TEST_ASSET, total)
	verify {
		assert_last_event::<T>(Event::Issued(TEST_ASSET, caller.clone(), total).into());
		assert_eq!(<TotalSupply<T>>::get(TEST_ASSET), total);
	}

	transfer_asset {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, TEST_ASSET, 1_000);
		assert!(Module::<T>::init_asset(origin, TEST_ASSET, 1_000).is_ok());
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
			Event::Transferred(TEST_ASSET, caller.clone(), recipient.clone(), transfer_amount).into()
		);
		assert_eq!(Balances::<T>::get(&recipient, TEST_ASSET), transfer_amount);
	}


	mint_private_asset {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, TEST_ASSET, 1000);
		assert!(Module::<T>::init_asset(origin, TEST_ASSET, 1000).is_ok());
	}: mint_private_asset (
		RawOrigin::Signed(caller),
		precomputed_coins::TEST_MINT_10_PAYLOAD)
	verify {
		assert_eq!(<TotalSupply<T>>::get(TEST_ASSET), 1000);
		assert_eq!(<PoolBalance<T>>::get(TEST_ASSET), 10);
	}


	private_transfer {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, TEST_ASSET, 1000);
		assert!(Module::<T>::init_asset(origin.clone(), TEST_ASSET, 1000).is_ok());

		Module::<T>::mint_private_asset(origin.clone(), precomputed_coins::TEST_MINT_10_PAYLOAD).unwrap();
		Module::<T>::mint_private_asset(origin, precomputed_coins::TEST_MINT_11_PAYLOAD).unwrap();
	}: private_transfer (
		RawOrigin::Signed(caller.clone()),
		precomputed_coins::TEST_TRANSFER_PAYLOAD)
	verify {
		assert_last_event::<T>(Event::PrivateTransferred(caller.clone()).into());
		assert_eq!(<TotalSupply<T>>::get(TEST_ASSET), 1000);
		assert_eq!(<PoolBalance<T>>::get(TEST_ASSET), 21);
	}

	reclaim {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, TEST_ASSET, 1000);
		assert!(Module::<T>::init_asset(origin.clone(), TEST_ASSET, 1000).is_ok());

		Module::<T>::mint_private_asset(origin.clone(), precomputed_coins::TEST_MINT_10_PAYLOAD).unwrap();
		Module::<T>::mint_private_asset(origin, precomputed_coins::TEST_MINT_11_PAYLOAD).unwrap();

		// pre-computed reclaimed circuit for a receiver of 10 assets
		let reclaim_value = 11;

	}: reclaim (
		RawOrigin::Signed(caller.clone()),
		precomputed_coins::TEST_RECLAIM_PAYLOAD)
	verify {
		assert_last_event::<T>(
			Event::PrivateReclaimed(TEST_ASSET, caller.clone(), reclaim_value).into()
		);
		assert_eq!(<TotalSupply<T>>::get(TEST_ASSET), 1000);
		assert_eq!(<PoolBalance<T>>::get(TEST_ASSET), 10);
	}
}

#[cfg(test)]
mod tests {
	use super::{
		bench_composite::{ExtBuilder, Test},
		*,
	};
	use frame_support::assert_ok;

	#[test]
	fn init() {
		ExtBuilder::default().build().execute_with(|| {
			assert_ok!(test_benchmark_init_asset::<Test>());
		});
	}

	#[test]
	fn transfer_asset() {
		ExtBuilder::default().build().execute_with(|| {
			assert_ok!(test_benchmark_transfer_asset::<Test>());
		});
	}

	#[test]
	fn mint_asset() {
		ExtBuilder::default().build().execute_with(|| {
			assert_ok!(test_benchmark_mint_private_asset::<Test>());
		});
	}

	#[test]
	fn manta_transfer() {
		ExtBuilder::default().build().execute_with(|| {
			assert_ok!(test_benchmark_private_transfer::<Test>());
		});
	}

	#[test]
	fn reclaim() {
		ExtBuilder::default().build().execute_with(|| {
			assert_ok!(test_benchmark_reclaim::<Test>());
		});
	}
}
