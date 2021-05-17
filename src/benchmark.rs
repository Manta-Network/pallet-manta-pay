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

use super::*;
use ark_ff::vec;
use ark_std::{boxed::Box, primitive::str};
use data_encoding::BASE64;
use frame_benchmarking::{account, benchmarks, whitelisted_caller};
use frame_system::{RawOrigin, EventRecord};

const SEED: u32 = 0;

fn benchmark_helper<T: Config>(sender: T::Origin) {
	let mut mint_bytes = [0u8; 96];

	let mint_data =	BASE64
		.decode(b"UdmGpEUW6WUwJZdU1nKKxUNXCRIJdqipFY7Q3WPVa3BM6DRE/LGrx0B0QY2MdxikuuHt96SFMkGleUc0GQ/b41rCMvzhnYdnO19XCVmJHDpxHziwHSOKRm2bZX/rwJwH")
		.unwrap();
	mint_bytes.copy_from_slice(mint_data.as_ref());
	Module::<T>::mint_private_asset(sender.clone(), 10, mint_bytes).unwrap();

	let mint_data =	BASE64
		.decode(b"ePVtcyyTC95xbHdcRVqhN6SBS4zvDIsmPRbWZa2YyQhPhmKLMV+/QrKJ1rvbO0Lqpsu1IlST9AXY22Ybw/iDxcbVJOcI2C08k4m7N50Ir9V/9Wlvw7w8zfEx0wP+fDUO")
		.unwrap();
	mint_bytes.copy_from_slice(mint_data.as_ref());
	Module::<T>::mint_private_asset(sender.clone(), 10, mint_bytes).unwrap();

	let mint_data =	BASE64
		.decode(b"BbkHR/7EX2ylnwEIpGp0bniLvfR2AQCAnjFDMCiG6RhpkGPm7OI/3imiJHpkaPRZA5AjusJHWtLS/x6o2t4wU7OADIt/h+IkY/LtUkCHFZm6V6AoFr2YiIKCXWwI5+MC")
		.unwrap();
	mint_bytes.copy_from_slice(mint_data.as_ref());
	Module::<T>::mint_private_asset(sender.clone(), 10, mint_bytes).unwrap();

	let mint_data =	BASE64
		.decode(b"Qv2uaLsuLuNNU+T1HJUuqqoQOtJ9bO9nEwip3PGmgBfEoWShKUp76ncWyIRsOwNmTz0Rd6rol6+zQuh1GJYu0ZlNOK4Ax5d7Dt31O8RMMSCrhyEWE8F0fNj2g/Z8kgsO")
		.unwrap();
	mint_bytes.copy_from_slice(mint_data.as_ref());
	Module::<T>::mint_private_asset(sender, 10, mint_bytes).unwrap();
}

pub fn assert_last_event<T: Config>(generic_event: <T as Config>::Event)
{
	let events = frame_system::Module::<T>::events();
	let system_event: <T as frame_system::Config>::Event = generic_event.into();
	let EventRecord {event, .. } = &events[events.len() - 1];
	assert_eq!(event, &system_event);
}

benchmarks! {

	init_asset {
		let caller: T::AccountId = whitelisted_caller();
		let total = 1000u64;
	}: init_asset (RawOrigin::Signed(caller.clone()), total)
	verify {
		assert_last_event::<T>(RawEvent::Issued(caller.clone(), total).into());
		assert_eq!(<TotalSupply>::get(), total);
	}

	transfer_asset {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, 1000);
		assert!(Module::<T>::init_asset(origin, 1000).is_ok());
		let recipient: T::AccountId = account("recipient", 0, SEED);
		let recipient_lookup: <T::Lookup as StaticLookup>::Source = T::Lookup::unlookup(recipient.clone());
		let transfer_amount = 10;
		Init::put(true);
	}: transfer_asset(RawOrigin::Signed(caller.clone()), recipient_lookup, transfer_amount)
	verify {
		assert_last_event::<T>(RawEvent::Transferred(caller.clone(), recipient.clone(), transfer_amount).into());
		assert_eq!(Balances::<T>::get(&recipient), transfer_amount);
	}


	mint_private_asset {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, 1000);
		assert!(Module::<T>::init_asset(origin.clone(), 1000).is_ok());
		let amount = 10;

		let mut mint_bytes = [0u8; 96];

		let mint_data =	BASE64
			.decode(b"UdmGpEUW6WUwJZdU1nKKxUNXCRIJdqipFY7Q3WPVa3BM6DRE/LGrx0B0QY2MdxikuuHt96SFMkGleUc0GQ/b41rCMvzhnYdnO19XCVmJHDpxHziwHSOKRm2bZX/rwJwH")
			.unwrap();
		mint_bytes.copy_from_slice(mint_data.as_ref());

	}: mint_private_asset (
		RawOrigin::Signed(caller.clone()),
		10,
		mint_bytes)
	verify {
		assert_last_event::<T>(RawEvent::Minted(caller.clone(), amount).into());
		assert_eq!(TotalSupply::get(), 1000);
		assert_eq!(PoolBalance::get(), 10);
	}


	private_transfer {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, 1000);
		assert!(Module::<T>::init_asset(origin.clone(), 1000).is_ok());

		benchmark_helper::<T>(origin);

		// hardcoded sender
		let mut sender_bytes_1 = [0u8; 96];
		let sender_data_1 = BASE64
			.decode(b"TOg0RPyxq8dAdEGNjHcYpLrh7fekhTJBpXlHNBkP2+MgIkzsMzMRTvThgza1tf0NmB93IBVQfktQCCDorNpeMGH9EyeUUj2Oz1Y9BnQb0+rHAl9Ne1eaevfH2wT6LoQB")
			.unwrap();
		sender_bytes_1.copy_from_slice(sender_data_1.as_ref());

		let mut sender_bytes_2 = [0u8; 96];
		let sender_data_2 = BASE64
			.decode(b"T4ZiizFfv0Kyida72ztC6qbLtSJUk/QF2NtmG8P4g8XDX0rOcCM/4ZT0QQXcPbb3VZIQf3RQ67wVNM38d+LCQQTIFdSTS1TxETxUpd67jfZKICuSgxKwb5X+PBvMGxYu")
			.unwrap();
		sender_bytes_2.copy_from_slice(sender_data_2.as_ref());

		// hardcoded receiver
		let mut receiver_bytes_1 = [0u8; 80];
		let receiver_data_1 = BASE64
			.decode(b"0oTFuAQG8C21A2N30b4nqbOB5nfwIcrs1aER00EBvaKF0KxGrBcL736UyP/+oExnzVthf0U8CDG2/qmkXNm5mAAAAAAAAAAAAAAAAAAAAAA=")
			.unwrap();
		receiver_bytes_1.copy_from_slice(receiver_data_1.as_ref());

		let mut receiver_bytes_2 = [0u8; 80];
		let receiver_data_2 = BASE64
			.decode(b"2kH96Ae8wOdvi7nA87Cfy9f+ce0lu1YS1j27LQ1D/a1eO7lMQI14/kniLp2a2U3DLNa6EPoQL1VHEp+t5mb9uAAAAAAAAAAAAAAAAAAAAAA=")
			.unwrap();
		receiver_bytes_2.copy_from_slice(receiver_data_2.as_ref());

		// hardcoded proof
		let mut proof_bytes = [0u8; 192];
		let proof_data = BASE64
			.decode(b"Knwm6dXGrOqd4gC8xvoxQGsGcHdLlY2be4XesJqny6YvUk2h/1SnGxPJ9i059PKBK0NdaCAcR3/L0YMue3/P+NPKHrPG6hqs+Bs4MNE07NWcdMQb6wU3dWGL+sW7RXQXnlnOwp93jpgADpmb2uikCbhx87ulHG5F5c1u+NDipi/IJ4URqCNod4VFYP8EZPsDXOtnD62VT0izr6eN9eVjlLkgWrdDaLTsVsQ+tBVbxe0QHmhnQFT8TwCYOYPXx8EQ")
			.unwrap();
		proof_bytes.copy_from_slice(proof_data.as_ref());

	}: private_transfer (
		RawOrigin::Signed(caller.clone()),
		sender_bytes_1,
		sender_bytes_2,
		receiver_bytes_1,
		receiver_bytes_2,
		proof_bytes)
	verify {
		assert_last_event::<T>(RawEvent::PrivateTransferred(caller.clone()).into());
		assert_eq!(TotalSupply::get(), 1000);
		assert_eq!(PoolBalance::get(), 40);
	}


	reclaim {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, 1000);
		assert!(Module::<T>::init_asset(origin.clone(), 1000).is_ok());

		benchmark_helper::<T>(origin);

		// hardcoded sender
		let mut sender_bytes_1 = [0u8; 96];
		let sender_data_1 = BASE64
			.decode(b"aZBj5uziP94poiR6ZGj0WQOQI7rCR1rS0v8eqNreMFNE0zyXQhhHwhHVFz4+RPOdBePDoGhV6Z2qWwyifehdnWjAvTNBr+pmM7t6lYmDOtxBw4sTQQTV6Y92+R5jVYcS")
			.unwrap();
		sender_bytes_1.copy_from_slice(sender_data_1.as_ref());

		let mut sender_bytes_2 = [0u8; 96];
		let sender_data_2 = BASE64
			.decode(b"xKFkoSlKe+p3FsiEbDsDZk89EXeq6Jevs0LodRiWLtEK+hOGmfLz2MuOyFGPcHwqFgrh4Hg5WP/X/i3KcZyHIxxmVpjr69iYzEQLTaXthBEAxfFpk7kEicm9KTQ3rzPi")
			.unwrap();
		sender_bytes_2.copy_from_slice(sender_data_2.as_ref());

		// hardcoded receiver
		let mut receiver_bytes = [0u8; 80];
		let receiver_data = BASE64
			.decode(b"UvTwRWxxcRUtbfZD+6+RVdU4Y1u3+zs8NtHMhf8IUAw2nXLghBzOPfFmvkSa5c/nENmgUc/v7tCzJr7N48pY2AAAAAAAAAAAAAAAAAAAAAA=")
			.unwrap();
		receiver_bytes.copy_from_slice(receiver_data.as_ref());

		// hardcoded proof
		let mut proof_bytes = [0u8; 192];
		let proof_data = BASE64
			.decode(b"MhcUuv4fdhzOF8pDQduDQymqo493r2DxnNU7GN+1qIjWJhXRLhXMzN4DSXCEp6OYqzIdUd160s6czxwoNEBDEVUJ/MATzNxex+PdO+vNfGYPdSorOYNFY1qfLg8rC4ADJPngMea763k8xF9CDPbxwplDcnq1Riq83ig22uP+ioNSgQOXb8UEElNJpGE9acIRbmfJ9ZBn+zHWyWBqVf3vvAjNvGOoJcO2dbCkgVqQyE/2zvGej2fK8YtS93Ea4KuM")
			.unwrap();
		proof_bytes.copy_from_slice(proof_data.as_ref());

	}: reclaim (
		RawOrigin::Signed(caller.clone()),
		10,
		sender_bytes_1,
		sender_bytes_2,
		receiver_bytes,
		proof_bytes)
	verify {
		assert_last_event::<T>(RawEvent::PrivateReclaimed(caller.clone()).into());
		assert_eq!(TotalSupply::get(), 1000);
		assert_eq!(PoolBalance::get(), 30);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::bench_composite::{ExtBuilder, Test};
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
