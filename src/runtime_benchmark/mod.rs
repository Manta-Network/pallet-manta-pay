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
use ark_ff::vec;
use ark_std::{
	boxed::Box,
	primitive::str,
	rand::{RngCore, SeedableRng},
};
use frame_benchmarking::{account, benchmarks, whitelisted_caller};
use frame_system::{EventRecord, RawOrigin};
use manta_asset::{MantaAsset, Sampling, TEST_ASSET};
use rand_chacha::ChaCha20Rng;

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
		let total = 1000u64;
	}: init_asset (RawOrigin::Signed(caller.clone()), TEST_ASSET, total)
	verify {
		assert_last_event::<T>(RawEvent::Issued(TEST_ASSET, caller.clone(), total).into());
		assert_eq!(<TotalSupply>::get(TEST_ASSET), total);
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
			RawEvent::Transferred(TEST_ASSET, caller.clone(), recipient.clone(), transfer_amount).into()
		);
		assert_eq!(Balances::<T>::get(&recipient, TEST_ASSET), transfer_amount);
	}


	mint_private_asset {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, TEST_ASSET, 1000);
		assert!(Module::<T>::init_asset(origin, TEST_ASSET, 1000).is_ok());

		// pre-computed minting payload
		let payload = [
			0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 174, 68, 81, 145, 170, 131, 195, 40, 164,
			3, 145, 105, 129, 194, 118, 220, 168, 75, 18, 192, 126, 246, 234, 205, 81, 195, 81, 167,
			255, 192, 45, 57, 149, 176, 228, 64, 76, 190, 90, 45, 69, 178, 243, 97, 99, 207, 142, 220,
			58, 170, 35, 76, 89, 113, 127, 214, 131, 73, 172, 129, 166, 39, 125, 210, 208, 173, 165,
			249, 122, 149, 137, 224, 8, 212, 239, 13, 28, 191, 254, 61, 67, 23, 76, 110, 87, 92, 74,
			94, 246, 87, 253, 140, 20, 174, 160, 11,
		];

	}: mint_private_asset (
		RawOrigin::Signed(caller),
		payload)
	verify {
		assert_eq!(TotalSupply::get(TEST_ASSET), 1000);
		assert_eq!(PoolBalance::get(TEST_ASSET), 10);
	}


	private_transfer {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, TEST_ASSET, 1000);
		assert!(Module::<T>::init_asset(origin.clone(), TEST_ASSET, 1000).is_ok());

		let hash_param = HashParam::deserialize(HASH_PARAM.data).unwrap();
		let commit_param = CommitmentParam::deserialize(COMMIT_PARAM.data).unwrap();

		let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
		let mut sk = [0u8; 32];

		// mint the tokens
		rng.fill_bytes(&mut sk);
		let asset_1 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &10, &mut rng).unwrap();
		let payload = generate_mint_payload(&asset_1);
		Module::<T>::mint_private_asset(origin.clone(), payload).unwrap();

		rng.fill_bytes(&mut sk);
		let asset_2 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &11, &mut rng).unwrap();
		let payload = generate_mint_payload(&asset_2);
		Module::<T>::mint_private_asset(origin, payload).unwrap();

		// build the senders
		let sender_1 = SenderMetaData::build(hash_param.clone(), asset_1.clone(), &[asset_1.commitment]);
		let sender_2 = SenderMetaData::build(hash_param.clone(), asset_2.clone(), &[asset_2.commitment]);

		// pre-computed transaction payload
		let payload = [
			149, 176, 228, 64, 76, 190, 90, 45, 69, 178, 243, 97, 99, 207, 142, 220, 58, 170, 35,
			76, 89, 113, 127, 214, 131, 73, 172, 129, 166, 39, 125, 210, 158, 112, 214, 151, 226,
			246, 45, 4, 133, 25, 133, 60, 34, 169, 147, 141, 219, 134, 97, 123, 11, 161, 137, 130,
			121, 39, 89, 177, 255, 244, 131, 74, 76, 204, 218, 170, 64, 51, 209, 60, 41, 119, 32,
			218, 93, 220, 143, 159, 115, 100, 190, 61, 55, 231, 153, 83, 244, 127, 208, 203, 58,
			93, 45, 75, 175, 27, 35, 111, 49, 19, 81, 84, 208, 198, 6, 122, 163, 220, 188, 182,
			219, 22, 150, 103, 164, 33, 70, 15, 154, 94, 145, 185, 128, 253, 66, 229, 206, 127,
			113, 212, 166, 187, 56, 186, 80, 123, 89, 166, 197, 128, 206, 52, 181, 60, 206, 242,
			171, 164, 245, 168, 198, 235, 62, 253, 239, 81, 121, 86, 86, 232, 47, 107, 202, 92,
			213, 121, 192, 188, 170, 25, 196, 240, 8, 100, 214, 120, 209, 100, 12, 78, 244, 129,
			250, 59, 193, 105, 124, 254, 61, 43, 226, 235, 187, 247, 204, 47, 30, 40, 31, 154, 64,
			30, 72, 247, 15, 68, 130, 31, 205, 134, 156, 110, 180, 32, 161, 165, 59, 165, 186, 166,
			27, 102, 78, 208, 181, 22, 121, 205, 173, 83, 185, 71, 70, 151, 15, 135, 42, 62, 4, 60,
			220, 193, 222, 66, 170, 209, 202, 37, 5, 96, 192, 197, 35, 95, 161, 133, 223, 44, 226,
			27, 139, 151, 72, 201, 163, 145, 1, 68, 170, 250, 77, 82, 221, 253, 86, 151, 201, 26,
			86, 185, 247, 226, 116, 233, 183, 35, 77, 205, 142, 68, 242, 113, 218, 212, 167, 79,
			180, 187, 177, 72, 186, 76, 149, 176, 228, 64, 76, 190, 90, 45, 69, 178, 243, 97, 99,
			207, 142, 220, 58, 170, 35, 76, 89, 113, 127, 214, 131, 73, 172, 129, 166, 39, 125,
			210, 123, 87, 165, 103, 136, 51, 4, 252, 184, 187, 218, 54, 199, 64, 204, 233, 94, 195,
			237, 108, 8, 70, 63, 150, 114, 141, 58, 178, 224, 97, 23, 88, 117, 64, 148, 50, 33,
			177, 172, 34, 133, 16, 146, 169, 138, 254, 68, 224, 99, 89, 237, 45, 136, 136, 133, 47,
			251, 35, 30, 97, 235, 137, 40, 47, 168, 201, 80, 171, 119, 190, 170, 218, 161, 172,
			155, 233, 143, 255, 12, 68, 105, 108, 195, 37, 103, 224, 190, 162, 210, 236, 66, 4, 28,
			94, 172, 73, 136, 3, 191, 173, 14, 49, 16, 39, 59, 70, 121, 88, 77, 184, 7, 200, 101,
			17, 0, 4, 73, 88, 69, 131, 154, 199, 172, 44, 137, 0, 168, 136, 26, 104, 8, 193, 13,
			13, 218, 2, 119, 208, 246, 49, 151, 220, 55, 108, 55, 146, 140, 215, 254, 144, 14, 172,
			204, 201, 64, 103, 92, 116, 72, 176, 217, 252, 37, 178, 40, 110, 195, 79, 113, 238,
			124, 86, 16, 72, 95, 21, 158, 182, 46, 188, 60, 110, 30, 98, 3, 252, 182, 191, 35, 179,
			181, 37, 118, 127, 217, 69, 211, 244, 244, 89, 106, 229, 241, 136, 57, 72, 199, 203,
			79, 99, 121, 244, 38, 22, 253, 79, 199, 240, 184, 244, 95, 166, 44, 20, 219, 180, 59,
			246, 21, 117, 191, 97, 124, 19, 157, 190, 172, 179, 213, 160, 167, 213, 102, 209, 224,
			100, 188, 158, 138, 252, 217, 203, 147, 39, 65, 16, 1, 180, 248, 220, 137, 180, 232,
			235, 111, 178, 144, 62, 192, 152, 163, 137,
		];

	}: private_transfer (
		RawOrigin::Signed(caller.clone()),
		payload)
	verify {
		assert_last_event::<T>(RawEvent::PrivateTransferred(caller.clone()).into());
		assert_eq!(TotalSupply::get(TEST_ASSET), 1000);
		assert_eq!(PoolBalance::get(TEST_ASSET), 21);
	}

	reclaim {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, TEST_ASSET, 1000);
		assert!(Module::<T>::init_asset(origin.clone(), TEST_ASSET, 1000).is_ok());

		let hash_param = HashParam::deserialize(HASH_PARAM.data).unwrap();
		let commit_param = CommitmentParam::deserialize(COMMIT_PARAM.data).unwrap();

		let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
		let mut sk = [0u8; 32];

		// mint the tokens
		rng.fill_bytes(&mut sk);
		let asset_1 = MantaAsset::sample(&commit_param, &sk,&TEST_ASSET, &10, &mut rng).unwrap();
		let payload = generate_mint_payload(&asset_1);
		Module::<T>::mint_private_asset(origin.clone(), payload).unwrap();

		rng.fill_bytes(&mut sk);
		let asset_2 = MantaAsset::sample(&commit_param, &sk,&TEST_ASSET, &11, &mut rng).unwrap();
		let payload = generate_mint_payload(&asset_2);
		Module::<T>::mint_private_asset(origin, payload).unwrap();

		// build the senders
		let sender_1 = SenderMetaData::build(hash_param.clone(), asset_1.clone(), &[asset_1.commitment]);
		let sender_2 = SenderMetaData::build(hash_param.clone(), asset_2.clone(), &[asset_2.commitment]);

		// pre-computed reclaimed circuit for a receiver of 10 assets
		let reclaim_value = 11;
		let payload = [
			0, 0, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 149, 176, 228, 64, 76, 190, 90, 45,
			69, 178, 243, 97, 99, 207, 142, 220, 58, 170, 35, 76, 89, 113, 127, 214, 131, 73, 172,
			129, 166, 39, 125, 210, 158, 112, 214, 151, 226, 246, 45, 4, 133, 25, 133, 60, 34, 169,
			147, 141, 219, 134, 97, 123, 11, 161, 137, 130, 121, 39, 89, 177, 255, 244, 131, 74,
			76, 204, 218, 170, 64, 51, 209, 60, 41, 119, 32, 218, 93, 220, 143, 159, 115, 100, 190,
			61, 55, 231, 153, 83, 244, 127, 208, 203, 58, 93, 45, 75, 175, 27, 35, 111, 49, 19, 81,
			84, 208, 198, 6, 122, 163, 220, 188, 182, 219, 22, 150, 103, 164, 33, 70, 15, 154, 94,
			145, 185, 128, 253, 66, 229, 206, 127, 113, 212, 166, 187, 56, 186, 80, 123, 89, 166,
			197, 128, 206, 52, 181, 60, 206, 242, 171, 164, 245, 168, 198, 235, 62, 253, 239, 81,
			121, 86, 86, 232, 47, 107, 202, 92, 213, 121, 192, 188, 170, 25, 196, 240, 8, 100, 214,
			120, 209, 100, 12, 78, 244, 129, 250, 59, 193, 105, 124, 254, 61, 43, 149, 176, 228,
			64, 76, 190, 90, 45, 69, 178, 243, 97, 99, 207, 142, 220, 58, 170, 35, 76, 89, 113,
			127, 214, 131, 73, 172, 129, 166, 39, 125, 210, 123, 87, 165, 103, 136, 51, 4, 252,
			184, 187, 218, 54, 199, 64, 204, 233, 94, 195, 237, 108, 8, 70, 63, 150, 114, 141, 58,
			178, 224, 97, 23, 88, 117, 64, 148, 50, 33, 177, 172, 34, 133, 16, 146, 169, 138, 254,
			68, 224, 99, 89, 237, 45, 136, 136, 133, 47, 251, 35, 30, 97, 235, 137, 40, 47, 168,
			201, 80, 171, 119, 190, 170, 218, 161, 172, 155, 233, 143, 255, 12, 68, 215, 146, 234,
			43, 31, 8, 123, 197, 179, 223, 184, 42, 189, 168, 77, 250, 11, 190, 247, 230, 187, 101,
			80, 160, 168, 136, 133, 156, 233, 141, 161, 112, 29, 206, 144, 107, 213, 207, 97, 120,
			111, 224, 68, 213, 50, 148, 239, 137, 24, 43, 134, 126, 118, 112, 168, 90, 103, 17,
			147, 190, 118, 145, 85, 237, 90, 128, 98, 59, 63, 136, 26, 219, 11, 72, 179, 119, 246,
			203, 226, 183, 134, 77, 239, 255, 11, 228, 93, 77, 117, 225, 150, 66, 146, 13, 216, 23,
			5, 218, 114, 180, 255, 29, 105, 238, 143, 86, 51, 214, 17, 22, 64, 246, 6, 30, 131,
			149, 45, 31, 35, 109, 42, 93, 154, 115, 7, 104, 97, 114, 73, 238, 33, 100, 174, 123,
			85, 18, 92, 118, 108, 44, 32, 59, 94, 0, 104, 191, 82, 35, 221, 143, 72, 121, 127, 57,
			106, 249, 110, 68, 170, 101, 147, 232, 175, 78, 226, 175, 188, 118, 227, 184, 82, 130,
			83, 31, 242, 84, 80, 37, 24, 137, 59, 34, 19, 99, 111, 95, 137, 229, 212, 56, 239, 146,
		];


	}: reclaim (
		RawOrigin::Signed(caller.clone()),
		payload)
	verify {
		assert_last_event::<T>(
			RawEvent::PrivateReclaimed(TEST_ASSET, caller.clone(), reclaim_value).into()
		);
		assert_eq!(TotalSupply::get(TEST_ASSET), 1000);
		assert_eq!(PoolBalance::get(TEST_ASSET), 10);
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
