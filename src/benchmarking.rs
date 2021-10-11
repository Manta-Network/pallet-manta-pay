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
use ark_serialize::CanonicalDeserialize;
use ark_std::vec;
use frame_benchmarking::{account, benchmarks, impl_benchmark_test_suite, whitelisted_caller};
use frame_system::{EventRecord, RawOrigin};
use manta_api::{
	generate_mint_struct, generate_private_transfer_struct, generate_reclaim_struct,
	util::into_array_unchecked,
	zkp::{keys::write_zkp_keys, sample::*},
};
use manta_asset::TEST_ASSET;
use manta_crypto::{
	commitment_parameters, leaf_parameters, two_to_one_parameters, Groth16Pk, MantaSerDes,
};
use manta_data::{
	BuildMetadata, MintData, MINT_PAYLOAD_SIZE, PRIVATE_TRANSFER_PAYLOAD_SIZE, RECLAIM_PAYLOAD_SIZE,
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::{collections::HashMap, fs::File, io::Read, sync::Once};

static INIT: Once = Once::new();
fn manta_zkp_key_generation() {
	INIT.call_once(|| write_zkp_keys().unwrap());
}

/// load precomputed zkp key from storage
/// filename can only be "transfer_pk.bin" or "reclaim_pk.bin"
fn load_zkp_key(file_name: &str) -> Groth16Pk {
	assert!(file_name == "transfer_pk.bin" || file_name == "reclaim_pk.bin");
	manta_zkp_key_generation();

	let mut file = File::open(file_name).unwrap();
	let mut transfer_key_bytes: Vec<u8> = vec![];
	file.read_to_end(&mut transfer_key_bytes).unwrap();
	let buf: &[u8] = transfer_key_bytes.as_ref();
	Groth16Pk::deserialize_unchecked(buf).unwrap()
}

/// Return proving key for transfer
fn transfer_pk() -> Groth16Pk {
	load_zkp_key("transfer_pk.bin")
}

/// Return proving key for reclaim
fn reclaim_pk() -> Groth16Pk {
	load_zkp_key("reclaim_pk.bin")
}

/// Insert utxo to the commitment set
fn insert_utxo(utxo: &UTXO, commitment_set: &mut HashMap<u8, Vec<[u8; 32]>>) {
	let shard_index = shard_index(*utxo);
	let shard = commitment_set.entry(shard_index).or_default();
	shard.push(utxo.clone());
}

struct PrecomputedCoins {
	pub coin_1: [u8; MINT_PAYLOAD_SIZE],
	pub coin_2: [u8; MINT_PAYLOAD_SIZE],
	pub transfer_data: [u8; PRIVATE_TRANSFER_PAYLOAD_SIZE],
	pub reclaim_data: [u8; RECLAIM_PAYLOAD_SIZE],
}

/// Generate a precomputed coins
/// * coin_1: a private coin with TEST_ASSET and value 89757
/// * coin_2: a private coin with TEST_ASSET and value 89758
/// * transfer_data: [coin_1, coin_2] -> [coin_3: (TEST_ASSET, 100000), coin_4, (TEST_ASSET, 79515)]
/// * reclaim_data: [coin_1, coin_2] -> [coin_3: (TEST_ASSET, 100000), coin_4_public, (TEST_ASSET, 79515)]
fn precompute_coins() -> PrecomputedCoins {
	// setup parameters
	let (commit_params, leaf_params, two_to_one_params) = (
		commitment_parameters(),
		leaf_parameters(),
		two_to_one_parameters(),
	);

	let mut rng = ChaCha20Rng::from_seed([55u8; 32]);
	let mut ledger = HashMap::new();

	// generate a coin with id TEST_ASSET and value 89757
	let sender_1 = fixed_asset(&commit_params, &TEST_ASSET, &89_757, &mut rng);
	let coin_1 = generate_mint_struct(&sender_1);
	let mut coin_1_bytes = Vec::new();
	coin_1.serialize(&mut coin_1_bytes).unwrap();

	// generate a coin with id TEST_ASSET and value 89758
	let sender_2 = fixed_asset(&commit_params, &TEST_ASSET, &89_758, &mut rng);
	let coin_2 = generate_mint_struct(&sender_2);
	let mut coin_2_bytes = Vec::new();
	coin_2.serialize(&mut coin_2_bytes).unwrap();

	// transfer sender_1 and sender_2 to two receivers
	insert_utxo(&sender_1.utxo, &mut ledger);
	insert_utxo(&sender_2.utxo, &mut ledger);
	let sender_1_meta = sender_1
		.build(
			&leaf_params,
			&two_to_one_params,
			ledger.get(&shard_index(sender_1.utxo)).unwrap(),
		)
		.unwrap();
	let sender_2_meta = sender_2
		.build(
			&leaf_params,
			&two_to_one_params,
			ledger.get(&shard_index(sender_2.utxo)).unwrap(),
		)
		.unwrap();

	let receiver_1 = fixed_receiver(&commit_params, &TEST_ASSET, &100_000, &mut rng);
	let receiver_2 = fixed_receiver(&commit_params, &TEST_ASSET, &79_515, &mut rng);
	let mut transfer_bytes = Vec::new();
	let transfer_data = generate_private_transfer_struct(
		commit_params.clone(),
		leaf_params.clone(),
		two_to_one_params.clone(),
		&transfer_pk(),
		[sender_1_meta.clone(), sender_2_meta.clone()],
		[receiver_1, receiver_2],
		&mut rng,
	)
	.unwrap();
	transfer_data.serialize(&mut transfer_bytes).unwrap();

	// reclaim 79515 TEST_ASSET, 10000 transferred to a coin
	let receiver = fixed_receiver(&commit_params, &TEST_ASSET, &100_000, &mut rng);
	let reclaim_data = generate_reclaim_struct(
		commit_params,
		leaf_params,
		two_to_one_params,
		&reclaim_pk(),
		[sender_1_meta, sender_2_meta],
		receiver,
		79_515,
		&mut rng,
	)
	.unwrap();
	let mut reclaim_bytes = Vec::new();
	reclaim_data.serialize(&mut reclaim_bytes).unwrap();

	PrecomputedCoins {
		coin_1: into_array_unchecked(coin_1_bytes),
		coin_2: into_array_unchecked(coin_2_bytes),
		transfer_data: into_array_unchecked(transfer_bytes),
		reclaim_data: into_array_unchecked(reclaim_bytes),
	}
}

lazy_static::lazy_static! {
	static ref PRECOMPUTED_COINS: PrecomputedCoins = precompute_coins();
}

pub fn assert_last_event<T: Config>(generic_event: <T as Config>::Event) {
	let events = frame_system::Pallet::<T>::events();
	let system_event: <T as frame_system::Config>::Event = generic_event.into();
	let EventRecord { event, .. } = &events[events.len() - 1];
	assert_eq!(event, &system_event);
}

benchmarks! {
	init_asset {
		let caller: T::AccountId = whitelisted_caller();
		let total = 1000_000u128;
	}: init_asset (RawOrigin::Signed(caller.clone()), TEST_ASSET, total)
	verify {
		assert_last_event::<T>(Event::Issued(TEST_ASSET, caller.clone(), total).into());
		assert_eq!(<TotalSupply<T>>::get(TEST_ASSET), total);
	}

	mint_private_asset {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, TEST_ASSET, 1000000);
		assert!(Pallet::<T>::init_asset(origin, TEST_ASSET, 1000000).is_ok());
		let mut mint_bytes: Vec<u8> = Vec::new();
		mint_bytes.extend_from_slice(&PRECOMPUTED_COINS.coin_1);
		let mint_data = MintData::deserialize(&mut mint_bytes.as_ref()).unwrap();
	}: mint_private_asset (
		RawOrigin::Signed(caller),
		mint_data)
	verify {
		assert_eq!(TotalSupply::<T>::get(TEST_ASSET), 1000000);
		assert_eq!(PoolBalance::<T>::get(TEST_ASSET), 89757);
	}

}

impl_benchmark_test_suite!(
	PalletMantaPay,
	crate::mock::new_test_ext(),
	crate::mock::Test,
);
