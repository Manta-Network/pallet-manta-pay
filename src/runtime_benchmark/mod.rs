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
			94, 246, 87, 253, 140, 20, 174, 160, 11, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16
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

		let payload = [
			0, 0, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 76, 0, 20, 205, 78, 195, 181, 70, 96, 61,
			159, 183, 72, 20, 161, 92, 201, 194, 167, 251, 51, 67, 58, 57, 171, 180, 117, 67, 11, 88,
			69, 75, 42, 69, 70, 80, 25, 191, 222, 85, 73, 190, 155, 11, 135, 2, 52, 204, 122, 174, 97,
			34, 141, 246, 173, 134, 177, 112, 2, 249, 67, 176, 234, 85, 239, 203, 194, 253, 72, 204,
			190, 48, 145, 200, 213, 164, 152, 122, 226, 124, 40, 54, 245, 11, 88, 109, 42, 136, 91, 97,
			102, 19, 6, 141, 144, 11, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
		];
		Module::<T>::mint_private_asset(origin.clone(), payload).unwrap();

		let payload = [
			0, 0, 0, 0, 0, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 162, 133, 70, 150, 203, 252, 41, 60, 73,
			41, 19, 91, 79, 99, 189, 84, 56, 231, 2, 44, 154, 18, 106, 116, 226, 176, 197, 154, 124,
			153, 62, 187, 31, 246, 0, 234, 113, 173, 254, 239, 98, 151, 192, 100, 70, 33, 231, 232, 44,
			99, 246, 129, 213, 201, 10, 113, 171, 110, 137, 235, 253, 147, 100, 164, 146, 149, 74, 23,
			42, 243, 123, 32, 13, 152, 225, 130, 237, 255, 100, 170, 206, 183, 54, 247, 253, 106, 132,
			149, 99, 83, 250, 209, 80, 125, 228, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
		];
		Module::<T>::mint_private_asset(origin, payload).unwrap();

		// pre-computed transaction payload
		let payload = [
			42, 69, 70, 80, 25, 191, 222, 85, 73, 190, 155, 11, 135, 2, 52, 204, 122, 174, 97, 34, 141,
			246, 173, 134, 177, 112, 2, 249, 67, 176, 234, 85, 105, 176, 218, 56, 226, 252, 208, 249,
			169, 232, 4, 111, 86, 69, 168, 233, 1, 223, 22, 13, 169, 137, 1, 175, 212, 187, 242, 96,
			33, 165, 12, 153, 254, 117, 112, 255, 51, 17, 142, 54, 211, 13, 213, 250, 225, 191, 43, 44,
			212, 14, 217, 89, 119, 121, 83, 164, 78, 137, 22, 248, 114, 211, 70, 2, 31, 246, 0, 234,
			113, 173, 254, 239, 98, 151, 192, 100, 70, 33, 231, 232, 44, 99, 246, 129, 213, 201, 10,
			113, 171, 110, 137, 235, 253, 147, 100, 164, 154, 229, 177, 249, 239, 112, 216, 223, 104,
			40, 66, 233, 215, 184, 200, 174, 39, 75, 145, 0, 102, 19, 240, 126, 82, 211, 38, 169, 2,
			62, 9, 90, 183, 0, 235, 210, 8, 112, 200, 235, 197, 64, 84, 54, 161, 247, 98, 201, 251, 95,
			106, 146, 128, 237, 151, 128, 204, 237, 38, 44, 126, 86, 187, 1, 147, 154, 50, 224, 238,
			16, 121, 209, 197, 254, 174, 23, 31, 167, 94, 21, 15, 47, 143, 209, 149, 100, 232, 210,
			188, 2, 203, 17, 184, 101, 65, 203, 215, 54, 70, 244, 55, 218, 178, 126, 158, 57, 191, 248,
			53, 171, 180, 68, 143, 69, 35, 81, 74, 101, 64, 117, 187, 20, 108, 151, 82, 215, 180, 214,
			69, 71, 142, 216, 179, 253, 145, 67, 166, 172, 142, 206, 246, 83, 163, 254, 167, 45, 123,
			208, 240, 201, 194, 197, 117, 78, 116, 124, 89, 125, 148, 39, 29, 100, 18, 190, 38, 16,
			178, 5, 38, 10, 60, 119, 143, 188, 203, 55, 135, 15, 135, 2, 49, 239, 155, 4, 120, 253,
			195, 43, 95, 114, 192, 56, 9, 210, 118, 183, 177, 102, 157, 178, 4, 171, 151, 247, 11, 122,
			236, 105, 190, 197, 147, 41, 110, 247, 229, 84, 141, 27, 44, 241, 188, 52, 30, 167, 162,
			147, 148, 111, 106, 80, 84, 138, 187, 21, 24, 98, 66, 116, 157, 204, 196, 122, 138, 157,
			93, 178, 191, 227, 10, 187, 124, 207, 173, 108, 167, 164, 143, 172, 16, 231, 38, 21, 108,
			169, 75, 47, 113, 37, 138, 185, 5, 24, 151, 253, 234, 62, 165, 240, 22, 42, 227, 225, 222,
			55, 107, 11, 11, 160, 231, 95, 222, 141, 240, 210, 26, 60, 131, 64, 44, 151, 178, 218, 115,
			193, 156, 143, 160, 40, 118, 91, 165, 13, 196, 60, 180, 173, 122, 227, 7, 174, 132, 177, 8,
			110, 193, 162, 241, 85, 212, 252, 117, 123, 135, 241, 144, 9, 102, 213, 60, 33, 20, 246,
			103, 42, 22, 159, 97, 45, 83, 87, 182, 25, 199, 110, 48, 161, 120, 199, 246, 9, 79, 148, 4,
			168, 65, 93, 63, 158, 22, 116, 245, 82, 104, 208, 70, 36, 57, 185, 29, 192, 241, 10, 126,
			17, 17, 251, 150, 218, 68, 170, 23, 17, 48, 215, 70, 176, 105, 112, 231, 58, 99, 194, 57,
			10, 250, 225, 223, 4, 215, 231, 100, 66, 171, 202, 6, 89, 78, 253, 155, 215, 222, 158, 66,
			251, 63, 56, 31, 98, 236, 132, 201, 15, 249, 235, 216, 206, 129, 27, 170, 53, 199, 254,
			149, 91, 140, 233, 21, 24, 150, 208, 151, 142, 77, 22, 71, 225, 183, 242, 53, 99, 13, 206,
			140, 66, 78, 54, 39, 150, 95, 178, 157, 28, 33, 175, 39, 127, 204, 197, 207, 24,
		];

	}: private_transfer (
		RawOrigin::Signed(caller.clone()),
		payload)
	verify {
		assert_last_event::<T>(RawEvent::PrivateTransferred(caller.clone()).into());
		assert_eq!(TotalSupply::get(TEST_ASSET), 1000);
		assert_eq!(PoolBalance::get(TEST_ASSET), 47);
	}

	reclaim {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, TEST_ASSET, 1000);
		assert!(Module::<T>::init_asset(origin.clone(), TEST_ASSET, 1000).is_ok());

		let payload = [
			0, 0, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 29, 252, 178, 230, 89, 156, 206, 31,
			123, 185, 47, 254, 59, 230, 70, 187, 159, 78, 12, 5, 62, 110, 177, 148, 29, 159, 133,
			94, 154, 29, 45, 22, 125, 107, 215, 11, 95, 124, 177, 175, 241, 169, 173, 158, 254,
			239, 183, 72, 22, 248, 101, 223, 110, 214, 230, 193, 160, 40, 49, 165, 62, 149, 28,
			157, 137, 53, 35, 203, 215, 118, 105, 34, 241, 210, 201, 132, 38, 171, 84, 143, 181,
			72, 127, 157, 99, 59, 38, 51, 223, 143, 59, 210, 246, 199, 42, 7, 1, 2, 3, 4, 5, 6, 7,
			8, 9, 10, 11, 12, 13, 14, 15, 16
		];
		Module::<T>::mint_private_asset(origin.clone(), payload).unwrap();

		let payload = [
			0, 0, 0, 0, 0, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 65, 178, 217, 24, 253, 217, 73, 130,
			32, 116, 58, 201, 83, 85, 199, 220, 66, 90, 186, 138, 134, 37, 54, 111, 24, 141, 245,
			36, 53, 179, 115, 195, 243, 106, 42, 40, 184, 184, 116, 138, 0, 220, 12, 50, 241, 222,
			199, 117, 251, 183, 16, 53, 13, 115, 218, 107, 149, 72, 244, 187, 177, 77, 64, 95, 242,
			5, 121, 157, 216, 201, 238, 131, 75, 225, 21, 28, 227, 218, 168, 178, 152, 218, 95,
			230, 255, 145, 174, 114, 211, 215, 76, 98, 239, 132, 212, 2, 1, 2, 3, 4, 5, 6, 7,
			8, 9, 10, 11, 12, 13, 14, 15, 16
		];
		Module::<T>::mint_private_asset(origin, payload).unwrap();

		// pre-computed reclaimed circuit for a receiver of 10 assets
		let reclaim_value = 24;
		let payload = [
			0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 125, 107, 215, 11, 95, 124, 177, 175,
			241, 169, 173, 158, 254, 239, 183, 72, 22, 248, 101, 223, 110, 214, 230, 193, 160, 40,
			49, 165, 62, 149, 28, 157, 114, 241, 95, 39, 30, 215, 53, 11, 5, 54, 220, 213, 155,
			146, 163, 196, 120, 77, 57, 180, 85, 250, 181, 65, 217, 235, 86, 90, 228, 204, 112,
			255, 187, 8, 13, 227, 19, 9, 122, 231, 135, 43, 6, 237, 153, 0, 67, 20, 178, 190, 194,
			10, 149, 205, 147, 70, 198, 199, 192, 96, 215, 110, 132, 97, 243, 106, 42, 40, 184,
			184, 116, 138, 0, 220, 12, 50, 241, 222, 199, 117, 251, 183, 16, 53, 13, 115, 218, 107,
			149, 72, 244, 187, 177, 77, 64, 95, 33, 46, 182, 225, 88, 178, 250, 95, 132, 95, 110,
			21, 31, 2, 135, 0, 220, 159, 7, 136, 200, 30, 81, 2, 246, 177, 235, 208, 210, 188, 138,
			5, 222, 99, 38, 182, 26, 235, 234, 70, 63, 108, 87, 32, 250, 29, 183, 44, 171, 181,
			189, 65, 215, 138, 103, 214, 197, 131, 100, 168, 19, 114, 70, 222, 141, 43, 54, 161,
			127, 19, 214, 1, 162, 139, 208, 184, 59, 241, 134, 201, 46, 208, 81, 180, 20, 85, 78,
			20, 155, 0, 190, 182, 21, 163, 214, 193, 88, 8, 244, 128, 33, 121, 89, 165, 107, 27,
			225, 96, 71, 129, 160, 139, 149, 32, 236, 118, 51, 101, 254, 250, 188, 202, 249, 209,
			18, 96, 228, 164, 152, 215, 105, 11, 20, 43, 157, 228, 151, 109, 145, 99, 150, 95, 48,
			123, 247, 3, 196, 66, 201, 228, 231, 129, 89, 12, 94, 207, 233, 243, 191, 15, 81, 30,
			124, 212, 62, 183, 167, 91, 174, 161, 67, 21, 220, 157, 39, 51, 215, 64, 126, 127, 111,
			188, 139, 206, 36, 82, 71, 87, 211, 126, 93, 235, 31, 31, 180, 95, 128, 126, 128, 204,
			179, 103, 197, 9, 41, 149, 150, 213, 22, 81, 2, 139, 236, 186, 112, 32, 173, 254, 89,
			204, 146, 150, 194, 2, 129, 61, 25, 74, 33, 164, 142, 84, 111, 53, 219, 7, 196, 6, 32,
			246, 44, 65, 204, 246, 41, 33, 228, 112, 24, 156, 74, 143, 63, 6, 119, 176, 120, 72,
			47, 215, 248, 122, 204, 182, 182, 138, 136, 107, 24, 37, 117, 24, 110, 228, 179, 53,
			215, 210, 196, 230, 204, 138, 96, 101, 220, 111, 61, 182, 193, 13, 50, 4, 85, 189, 233,
			41, 189, 78, 215, 228, 36, 222, 218, 193, 183, 170, 147, 90, 107, 102, 94, 223, 217,
			29, 136, 248, 166, 4, 125, 1, 149, 118, 154, 83, 246, 152, 179, 163, 46, 198, 163, 215,
			108, 170, 244, 147, 96, 240, 241, 96, 184, 5, 26, 186, 223, 69, 11, 250, 78, 54, 19,
			63, 158, 40, 210, 38, 232, 159, 49, 173, 140, 57, 6, 227, 195, 69, 169, 25,
		];

	}: reclaim (
		RawOrigin::Signed(caller.clone()),
		payload)
	verify {
		assert_last_event::<T>(
			RawEvent::PrivateReclaimed(TEST_ASSET, caller.clone(), reclaim_value).into()
		);
		assert_eq!(TotalSupply::get(TEST_ASSET), 1000);
		assert_eq!(PoolBalance::get(TEST_ASSET), 23);
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
