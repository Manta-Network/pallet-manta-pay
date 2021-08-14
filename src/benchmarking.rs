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
use super::*;

#[allow(unused)]
use crate::Pallet as PalletMantaPay;
use frame_benchmarking::{account, benchmarks, impl_benchmark_test_suite, whitelisted_caller};
use frame_system::{EventRecord, RawOrigin};
use manta_asset::TEST_ASSET;

const SEED: u32 = 0;

pub fn assert_last_event<T: Config>(generic_event: <T as Config>::Event) {
	let events = frame_system::Pallet::<T>::events();
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

	add_coin_in_map {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
	}: (0u128...10_000u128).map(|x| add_coin_in_map(origin, x))
	verify {
		assert_last_event::<T>(
			Event::PrivateTransferred(caller.clone())
		);
	}

	add_coin_in_map {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
	}: (0u128...10_000u128).map(|x| add_coin_in_vec(origin, x))
	verify {
		assert_last_event::<T>(
			Event::PrivateTransferred(caller.clone())
		);
	}
}

impl_benchmark_test_suite!(
	PalletMantaPay,
	crate::mock::new_test_ext(),
	crate::mock::Test,
);
