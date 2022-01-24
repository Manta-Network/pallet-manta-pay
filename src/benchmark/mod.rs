// Copyright 2019-2022 Manta Network.
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

use crate::Pallet;
use frame_benchmarking::{account, benchmarks, impl_benchmark_test_suite, whitelisted_caller};
use frame_system::RawOrigin;
use sp_runtime::traits::StaticLookup;

///
const SEED: u32 = 0;

///
#[inline]
pub fn assert_last_event<T, E>(event: E)
where
	T: Config,
	E: Into<<T as Config>::Event>,
{
	let events = frame_system::Pallet::<T>::events();
	assert_eq!(events[events.len() - 1].event, event.into().into());
}

benchmarks! {
	transfer_asset {
		let caller: T::AccountId = whitelisted_caller();
		let origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		Pallet::<T>::init_asset(&caller, 0, 1_000);
		let recipient: T::AccountId = account("recipient", 0, SEED);
		let recipient_lookup = T::Lookup::unlookup(recipient.clone());
		let asset = Asset::new(0, 10);
	}: transfer_asset (
		RawOrigin::Signed(caller.clone()),
		recipient_lookup,
		asset
	) verify {
		assert_last_event::<T, _>(Event::Transfer { asset, source: caller, sink: recipient.clone() });
		assert_eq!(Balances::<T>::get(recipient, asset.id), asset.value);
	}

	/*
	mint {
		let caller: T::AccountId = whitelisted_caller();
		let origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		Pallet::<T>::init_asset(&caller, 0, 1_000_000);
		let mint_post = TransferPost::decode(MINT_0).unwrap();
		let asset = Asset::new(mint_post.asset_id.unwrap(), mint_post.sources[0]);
	}: mint (
		RawOrigin::Signed(caller),
		mint_post
	) verify {
		assert_last_event::<T, _>(Event::Mint { asset, source: caller.clone() });
		assert_eq!(Balances::<T>::get(caller, asset.id), 1_000_000 - asset.value);
	}

	private_transfer {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, TEST_ASSET, 1_000_000);
		Pallet::<T>::init_asset(&caller, TEST_ASSET, 1_000_000);

		for coin in [COIN_1, COIN_2] {
			let mut coin_bytes: Vec<u8> = Vec::new();
			coin_bytes.extend_from_slice(coin);
			let mint_data = MintData::deserialize(&mut coin_bytes.as_ref()).unwrap();
			Pallet::<T>::mint(origin.clone(), mint_data).unwrap();
		}

		let mut test_transfer_bytes: Vec<u8> = Vec::new();
		test_transfer_bytes.extend_from_slice(TRANSFER_DATA);
		let transfer_data = PrivateTransferData::deserialize(&mut test_transfer_bytes.as_ref()).unwrap();

	}: private_transfer (
		RawOrigin::Signed(caller.clone()),
		transfer_data)
	verify {
		assert_last_event::<T>(Event::PrivateTransfer(caller).into());
		assert_eq!(TotalSupply::<T>::get(TEST_ASSET), 1_000_000);
		assert_eq!(PoolBalance::<T>::get(TEST_ASSET), 179_515);
	}

	reclaim {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, TEST_ASSET, 1_000_000);
		Pallet::<T>::init_asset(&caller, TEST_ASSET, 1_000_000);

		for coin in [COIN_1, COIN_2] {
			let mut coin_bytes: Vec<u8> = Vec::new();
			coin_bytes.extend_from_slice(coin);
			let mint_data = MintData::deserialize(&mut coin_bytes.as_ref()).unwrap();
			Pallet::<T>::mint(origin.clone(), mint_data).unwrap();
		}

		let mut reclaim_bytes: Vec<u8> = Vec::new();
		reclaim_bytes.extend_from_slice(RECLAIM_DATA);
		let reclaim_data = ReclaimData::deserialize(&mut reclaim_bytes.as_ref()).unwrap();
	}: reclaim (
		RawOrigin::Signed(caller.clone()),
		reclaim_data
	)
	verify {
		assert_last_event::<T>(Event::Reclaim(TEST_ASSET, caller, 79_515).into());
		assert_eq!(TotalSupply::<T>::get(TEST_ASSET), 1_000_000);
		assert_eq!(PoolBalance::<T>::get(TEST_ASSET), 100_000);
	}
	*/
}

impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
