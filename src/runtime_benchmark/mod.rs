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
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
	boxed::Box,
	primitive::str,
	rand::{RngCore, SeedableRng},
};
use data_encoding::BASE64;
use frame_benchmarking::{account, benchmarks, whitelisted_caller};
use frame_system::{EventRecord, RawOrigin};
use pallet_manta_asset::{MantaAsset, MantaAssetFullReceiver, Process, Sampling};
use rand_chacha::ChaCha20Rng;
use std::{fs::File, io::Read};

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
	}: init_asset (RawOrigin::Signed(caller.clone()), total)
	verify {
		assert_last_event::<T>(RawEvent::Issued(caller.clone(), total).into());
		assert_eq!(<TotalSupply>::get(), total);
	}

	transfer_asset {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, 1_000);
		assert!(Module::<T>::init_asset(origin, 1_000).is_ok());
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
		assert!(Module::<T>::init_asset(origin, 1000).is_ok());

		let amount = 10u64;
		let mut payload = [0u8; 104];
		payload[0..8].copy_from_slice(amount.to_le_bytes().as_ref());

		let mint_data =	BASE64
			.decode(b"UdmGpEUW6WUwJZdU1nKKxUNXCRIJdqipFY7Q3WPVa3BM6DRE/LGrx0B0QY2MdxikuuHt96SFMkGleUc0GQ/b41rCMvzhnYdnO19XCVmJHDpxHziwHSOKRm2bZX/rwJwH")
			.unwrap();
			payload[8..104].copy_from_slice(mint_data.as_ref());

	}: mint_private_asset (
		RawOrigin::Signed(caller),
		payload)
	verify {
		assert_eq!(TotalSupply::get(), 1000);
		assert_eq!(PoolBalance::get(), 10);
	}


	private_transfer {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, 1000);
		assert!(Module::<T>::init_asset(origin.clone(), 1000).is_ok());

		let hash_param = HashParam::deserialize(HASH_PARAM.data);
		let commit_param = CommitmentParam::deserialize(COMMIT_PARAM.data);

		// load the ZKP keys
		let mut file = File::open("transfer_pk.bin").unwrap();
		let mut transfer_key_bytes: Vec<u8> = vec![];
		file.read_to_end(&mut transfer_key_bytes).unwrap();
		let buf: &[u8] = transfer_key_bytes.as_ref();
		let pk = Groth16Pk::deserialize_unchecked(buf).unwrap();
		let vk = pk.vk.clone();
		let mut vk_bytes = Vec::new();
		vk.serialize_uncompressed(&mut vk_bytes).unwrap();
		let vk = TRANSFER_PK;
		let vk_checksum = TransferZKPKeyChecksum::get();
		assert_eq!(vk.get_checksum(), vk_checksum);

		let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
		let mut sk = [0u8; 32];

		// mint the tokens
		let mut payload = [0u8; 104];
		rng.fill_bytes(&mut sk);
		let asset_1 = MantaAsset::sample(&commit_param, &sk, &15, &mut rng);
		let mint_data_1 = generate_mint_payload(&asset_1);
		mint_data_1.serialize(payload.as_mut());
		Module::<T>::mint_private_asset(origin.clone(), payload).unwrap();

		rng.fill_bytes(&mut sk);
		let asset_2 = MantaAsset::sample(&commit_param, &sk, &25, &mut rng);
		let mint_data_2 = generate_mint_payload(&asset_2);
		mint_data_2.serialize(payload.as_mut());
		Module::<T>::mint_private_asset(origin, payload).unwrap();

		// build the senders
		let sender_1 = SenderMetaData::build(hash_param.clone(), asset_1.clone(), &[asset_1.commitment]);
		let sender_2 = SenderMetaData::build(hash_param.clone(), asset_2.clone(), &[asset_2.commitment]);

		// extract the receivers
		rng.fill_bytes(&mut sk);
		let receiver_full_1 = MantaAssetFullReceiver::sample(&commit_param, &sk, &(), &mut rng);
		let receiver_1 = receiver_full_1.prepared.process(&10, &mut rng);

		rng.fill_bytes(&mut sk);
		let receiver_full_2 = MantaAssetFullReceiver::sample(&commit_param, &sk, &(), &mut rng);
		let receiver_2 = receiver_full_1.prepared.process(&30, &mut rng);

		// form the transaction payload
		let transfer_data = generate_private_transfer_payload(
			commit_param.clone(),
			hash_param.clone(),
			&pk,
			sender_1,
			sender_2,
			receiver_1.clone(),
			receiver_2.clone(),
			&mut rng,
		);
		let mut payload = [0; 608];
		transfer_data.serialize(payload.as_mut());

	}: private_transfer (
		RawOrigin::Signed(caller.clone()),
		payload)
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

		let hash_param = HashParam::deserialize(HASH_PARAM.data);
		let commit_param = CommitmentParam::deserialize(COMMIT_PARAM.data);

		// load the ZKP keys
		let mut file = File::open("reclaim_pk.bin").unwrap();
		let mut transfer_key_bytes: Vec<u8> = vec![];
		file.read_to_end(&mut transfer_key_bytes).unwrap();
		let buf: &[u8] = transfer_key_bytes.as_ref();
		let pk = Groth16Pk::deserialize_unchecked(buf).unwrap();
		let vk = pk.vk.clone();
		let mut vk_bytes = Vec::new();
		vk.serialize_uncompressed(&mut vk_bytes).unwrap();
		let vk = TRANSFER_PK;
		let vk_checksum = TransferZKPKeyChecksum::get();
		assert_eq!(vk.get_checksum(), vk_checksum);

		let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
		let mut sk = [0u8; 32];

		// mint the tokens
		let mut payload = [0u8; 104];
		rng.fill_bytes(&mut sk);
		let asset_1 = MantaAsset::sample(&commit_param, &sk, &15, &mut rng);
		let mint_data_1 = generate_mint_payload(&asset_1);
		mint_data_1.serialize(payload.as_mut());
		Module::<T>::mint_private_asset(origin.clone(), payload).unwrap();

		rng.fill_bytes(&mut sk);
		let asset_2 = MantaAsset::sample(&commit_param, &sk, &25, &mut rng);
		let mint_data_2 = generate_mint_payload(&asset_2);
		mint_data_2.serialize(payload.as_mut());
		Module::<T>::mint_private_asset(origin, payload).unwrap();

		// build the senders
		let sender_1 = SenderMetaData::build(hash_param.clone(), asset_1.clone(), &[asset_1.commitment]);
		let sender_2 = SenderMetaData::build(hash_param.clone(), asset_2.clone(), &[asset_2.commitment]);

		// extract the receivers
		rng.fill_bytes(&mut sk);
		let reclaim_value = 30;
		let receiver_full = MantaAssetFullReceiver::sample(&commit_param, &sk, &(), &mut rng);
		let receiver = receiver_full.prepared.process(&10, &mut rng);

		// form the transaction payload
		let reclaim_data = generate_reclaim_payload(
			commit_param.clone(),
			hash_param.clone(),
			&pk,
			sender_1.clone(),
			sender_2.clone(),
			receiver,
			reclaim_value,
			&mut rng,
		);
		let mut payload = [0; 504];
		reclaim_data.serialize(payload.as_mut());

	}: reclaim (
		RawOrigin::Signed(caller.clone()),
		payload)
	verify {
		assert_last_event::<T>(RawEvent::PrivateReclaimed(caller.clone()).into());
		assert_eq!(TotalSupply::get(), 1000);
		assert_eq!(PoolBalance::get(), 10);
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
