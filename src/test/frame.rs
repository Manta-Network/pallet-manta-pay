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

use crate as pallet_manta_pay;
use crate::*;
use manta_crypto::*;
use pallet_manta_asset::*;
use ark_groth16::create_random_proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{RngCore, SeedableRng};
use frame_support::{assert_noop, assert_ok, parameter_types};
use rand_chacha::ChaCha20Rng;
use sp_core::H256;
use sp_runtime::{
	testing::Header,
	traits::{BlakeTwo256, IdentityLookup},
};
use std::{boxed::Box, fs::File, io::prelude::*, string::String};
// use x25519_dalek::{PublicKey, StaticSecret};

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
	pub enum Test where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = UncheckedExtrinsic,
	{
		System: frame_system::{Module, Call, Config, Storage, Event<T>},
		MantaModule: pallet_manta_pay::{Module, Call, Storage, Event<T>},
	}
);
type BlockNumber = u64;

parameter_types! {
	pub const BlockHashCount: BlockNumber = 250;
	pub const SS58Prefix: u8 = 42;
}

impl frame_system::Config for Test {
	type BaseCallFilter = ();
	type Origin = Origin;
	type Index = u64;
	type Call = Call;
	type BlockNumber = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = u64;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Header = Header;
	type Event = ();
	type BlockHashCount = BlockHashCount;
	type DbWeight = ();
	type Version = ();
	type AccountData = ();
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type PalletInfo = PalletInfo;
	type BlockWeights = ();
	type BlockLength = ();
	type SS58Prefix = SS58Prefix;
}

impl Config for Test {
	type Event = ();
}
type Assets = Module<Test>;

fn new_test_ext() -> sp_io::TestExternalities {
	frame_system::GenesisConfig::default()
		.build_storage::<Test>()
		.unwrap()
		.into()
}

#[test]
fn test_constants_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init_asset(Origin::signed(1), 100));
		assert_eq!(Assets::balance(1), 100);
		let hash_param = HashParam::deserialize(HASH_PARAM.data);
		let commit_param = CommitmentParam::deserialize(COMMIT_PARAM.data);
		let hash_param_checksum_local = hash_param.get_checksum();
		let commit_param_checksum_local = commit_param.get_checksum();
		let hash_param_checksum = HashParamChecksum::get();
		let commit_param_checksum = CommitParamChecksum::get();
		assert_eq!(hash_param_checksum, hash_param_checksum_local);
		assert_eq!(commit_param_checksum, commit_param_checksum_local);
	});
}

#[test]
fn test_mint_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init_asset(Origin::signed(1), 1000));
		assert_eq!(Assets::balance(1), 1000);
		assert_eq!(PoolBalance::get(), 0);
		let commit_param = CommitmentParam::deserialize(COMMIT_PARAM.data);
		let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
		let mut sk = [0u8; 32];
		rng.fill_bytes(&mut sk);
		let asset = MantaAsset::sample(&commit_param, &sk, &10, &mut rng);

		let mut mint_data = [0u8; 96];
		mint_data.copy_from_slice(
			[asset.commitment.clone(), asset.pub_info.k, asset.pub_info.s]
				.concat()
				.as_ref(),
		);

		assert_ok!(Assets::mint_private_asset(Origin::signed(1), 10, mint_data));

		assert_eq!(TotalSupply::get(), 1000);
		assert_eq!(PoolBalance::get(), 10);
		let coin_shards = CoinShards::get();
		assert!(coin_shards.exist(&asset.commitment));
		let sn_list = VNList::get();
		assert_eq!(sn_list.len(), 0);
	});
}

#[test]
fn test_transfer_should_work() {
	new_test_ext().execute_with(|| transfer_test_helper(5));
}

#[ignore]
#[test]
fn test_transfer_should_work_super_long() {
	new_test_ext().execute_with(|| transfer_test_helper(400));
}

#[test]
fn test_reclaim_should_work() {
	new_test_ext().execute_with(|| reclaim_test_helper(5));
}

#[ignore]
#[test]
fn test_reclaim_should_work_super_long() {
	new_test_ext().execute_with(|| reclaim_test_helper(400));
}

#[test]
fn issuing_asset_units_to_issuer_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init_asset(Origin::signed(1), 100));
		assert_eq!(Assets::balance(1), 100);
	});
}

#[test]
fn querying_total_supply_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init_asset(Origin::signed(1), 100));
		assert_eq!(Assets::balance(1), 100);
		assert_ok!(Assets::transfer_asset(Origin::signed(1), 2, 50));
		assert_eq!(Assets::balance(1), 50);
		assert_eq!(Assets::balance(2), 50);
		assert_ok!(Assets::transfer_asset(Origin::signed(2), 3, 31));
		assert_eq!(Assets::balance(1), 50);
		assert_eq!(Assets::balance(2), 19);
		assert_eq!(Assets::balance(3), 31);
		assert_eq!(Assets::total_supply(), 100);
	});
}

#[test]
fn transferring_amount_above_available_balance_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init_asset(Origin::signed(1), 100));
		assert_eq!(Assets::balance(1), 100);
		assert_ok!(Assets::transfer_asset(Origin::signed(1), 2, 50));
		assert_eq!(Assets::balance(1), 50);
		assert_eq!(Assets::balance(2), 50);
	});
}

#[test]
fn transferring_amount_more_than_available_balance_should_not_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init_asset(Origin::signed(1), 100));
		assert_eq!(Assets::balance(1), 100);
		assert_ok!(Assets::transfer_asset(Origin::signed(1), 2, 50));
		assert_eq!(Assets::balance(1), 50);
		assert_eq!(Assets::balance(2), 50);
		assert_noop!(
			Assets::transfer_asset(Origin::signed(1), 1, 60),
			Error::<Test>::BalanceLow
		);
	});
}

#[test]
fn transferring_less_than_one_unit_should_not_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init_asset(Origin::signed(1), 100));
		assert_eq!(Assets::balance(1), 100);
		assert_noop!(
			Assets::transfer_asset(Origin::signed(1), 2, 0),
			Error::<Test>::AmountZero
		);
	});
}

#[test]
fn transferring_more_units_than_total_supply_should_not_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init_asset(Origin::signed(1), 100));
		assert_eq!(Assets::balance(1), 100);
		assert_noop!(
			Assets::transfer_asset(Origin::signed(1), 2, 101),
			Error::<Test>::BalanceLow
		);
	});
}

#[test]
fn destroying_asset_balance_with_positive_balance_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init_asset(Origin::signed(1), 100));
		assert_eq!(Assets::balance(1), 100);
	});
}

#[test]
fn cannot_init_twice() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init_asset(Origin::signed(1), 100));
		assert_noop!(
			Assets::init_asset(Origin::signed(1), 100),
			Error::<Test>::AlreadyInitialized
		);
	});
}

fn mint_tokens_helper(size: usize) -> Vec<MantaAsset> {
	let commit_param = CommitmentParam::deserialize(COMMIT_PARAM.data);

	let mut rng = ChaCha20Rng::from_seed([88u8; 32]);
	let mut pool = 0;
	let mut sk = [0u8; 32];

	// sender tokens
	let mut senders = Vec::new();
	for i in 0usize..size {
		// build a sender token
		let token_value = 10 + i as u64;
		rng.fill_bytes(&mut sk);
		let asset = MantaAsset::sample(&commit_param, &sk, &token_value, &mut rng);


		let mut mint_data = [0u8; 96];
		mint_data.copy_from_slice(
			[asset.commitment.clone(), asset.pub_info.k, asset.pub_info.s]
			.concat()
			.as_ref(),
		);

		// mint a sender token
		assert_ok!(Assets::mint_private_asset(
			Origin::signed(1),
			token_value,
			mint_data
		));

		pool += token_value;

		// sanity checks
		assert_eq!(PoolBalance::get(), pool);
		let coin_shards = CoinShards::get();
		assert!(coin_shards.exist(&asset.commitment));
		senders.push(asset);
	}
	senders
}

fn transfer_test_helper(iter: usize) {
	// setup
	assert_ok!(Assets::init_asset(Origin::signed(1), 10_000_000));
	assert_eq!(Assets::balance(1), 10_000_000);
	assert_eq!(PoolBalance::get(), 0);

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

	let size = iter << 1;
	let senders = mint_tokens_helper(size);
	let pool = PoolBalance::get();

	let sn_list = VNList::get();
	assert_eq!(sn_list.len(), 0);

	// build receivers
	let mut receivers_full = Vec::new();
	let mut receivers_processed = Vec::new();
	for i in 0usize..size {
		// build a receiver token
		rng.fill_bytes(&mut sk);
		let receiver_full = MantaAssetFullReceiver::sample(&commit_param, &sk, &(), &mut rng);
		let receiver = receiver_full.prepared.process(&(i as u64 + 10));
		receivers_full.push(receiver_full);
		receivers_processed.push(receiver);
	}

	for i in 0usize..iter {
		let coin_shards = CoinShards::get();
		let sender_1 = senders[i * 2].clone();
		let sender_2 = senders[i * 2 + 1].clone();
		let receiver_1 = receivers_processed[i * 2 + 1].clone();
		let receiver_2 = receivers_processed[i * 2].clone();

		let shard_index_1 = sender_1.commitment[0] as usize;
		let shard_index_2 = sender_2.commitment[0] as usize;

		// generate the merkle trees
		let list_1 = coin_shards.shard[shard_index_1].list.clone();
		let tree_1 = LedgerMerkleTree::new(hash_param.clone(), &list_1).unwrap();
		let merkle_root_1 = tree_1.root();

		let index_1 = list_1
			.iter()
			.position(|x| *x == sender_1.commitment)
			.unwrap();
		let path_1 = tree_1
			.generate_proof(index_1, &sender_1.commitment)
			.unwrap();

		let list_2 = coin_shards.shard[shard_index_2].list.clone();
		let tree_2 = LedgerMerkleTree::new(hash_param.clone(), &list_2).unwrap();
		let merkle_root_2 = tree_2.root();

		let index_2 = list_2
			.iter()
			.position(|x| *x == sender_2.commitment)
			.unwrap();
		let path_2 = tree_2
			.generate_proof(index_2, &sender_2.commitment)
			.unwrap();

		// generate circuit
		let circuit = TransferCircuit {
			commit_param: commit_param.clone(),
			hash_param: hash_param.clone(),

			sender_1: sender_1.clone(),
			sender_membership_1: path_1,
			root_1: merkle_root_1,

			sender_2: sender_2.clone(),
			sender_membership_2: path_2,
			root_2: merkle_root_2,

			receiver_1: receiver_1.clone(),
			receiver_2: receiver_2.clone(),
		};

		// generate ZKP
		let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();
		let mut proof_bytes = [0u8; 192];
		proof.serialize(proof_bytes.as_mut()).unwrap();

		// // ciphertexts
		// let receiver_sk_1 = StaticSecret::new(&mut rng);
		// let receiver_pk_1 = PublicKey::from(&receiver_sk_1);
		// let receiver_pk_bytes_1 = receiver_pk_1.to_bytes();
		// let receiver_sk_bytes_1 = receiver_sk_1.to_bytes();
		// let (sender_pk_bytes_1, cipher_1) =
		// 	manta_dh_enc(&receiver_pk_bytes_1, receiver_1.2.value, &mut rng);

		// let receiver_sk_2 = StaticSecret::new(&mut rng);
		// let receiver_pk_2 = PublicKey::from(&receiver_sk_2);
		// let receiver_pk_bytes_2 = receiver_pk_2.to_bytes();
		// let receiver_sk_bytes_2 = receiver_sk_2.to_bytes();
		// let (sender_pk_bytes_2, cipher_2) =
		// 	crypto::manta_dh_enc(&receiver_pk_bytes_2, receiver_2.2.value, &mut rng);

		// make the transfer inputs
		let mut sender_data_1 = [0u8; 96];
		sender_data_1.copy_from_slice(
			[
				sender_1.pub_info.k.as_ref(),
				sender_1.void_number.as_ref(),
				coin_shards.shard[shard_index_1].root.as_ref(),
			]
			.concat()
			.as_ref(),
		);

		let mut sender_data_2 = [0u8; 96];
		sender_data_2.copy_from_slice(
			[
				sender_2.pub_info.k.as_ref(),
				sender_2.void_number.as_ref(),
				coin_shards.shard[shard_index_2].root.as_ref(),
			]
			.concat()
			.as_ref(),
		);

		let mut receiver_data_1 = [0u8; 80];
		receiver_data_1.copy_from_slice(
			[
				receiver_1.prepared_data.k.as_ref(),
				receiver_1.commitment.as_ref(),
				// cipher_1.as_ref(),
				&[0u8; 16],
			]
			.concat()
			.as_ref(),
		);

		let mut receiver_data_2 = [0u8; 80];
		receiver_data_2.copy_from_slice(
			[
				receiver_2.prepared_data.k.as_ref(),
				receiver_2.commitment.as_ref(),
				// cipher_2.as_ref(),
				&[0u8; 16],
			]
			.concat()
			.as_ref(),
		);
		// invoke the transfer event
		assert_ok!(Assets::private_transfer(
			Origin::signed(1),
			sender_data_1,
			sender_data_2,
			receiver_data_1,
			receiver_data_2,
			proof_bytes,
		));

		// // check the ciphertexts
		// let enc_value_list = EncValueList::get();
		// assert_eq!(enc_value_list.len(), 2 * (i + 1));
		// assert_eq!(enc_value_list[2 * i], cipher_1);
		// assert_eq!(enc_value_list[2 * i + 1], cipher_2);
		// assert_eq!(
		// 	crypto::manta_dh_dec(&cipher_1, &sender_pk_bytes_1, &receiver_sk_bytes_1),
		// 	receiver_1.2.value
		// );
		// assert_eq!(
		// 	crypto::manta_dh_dec(&cipher_2, &sender_pk_bytes_2, &receiver_sk_bytes_2),
		// 	receiver_2.2.value
		// );

		assert_eq!(PoolBalance::get(), pool);
	}

	// check the resulting status of the ledger storage
	assert_eq!(TotalSupply::get(), 10_000_000);
	let coin_shards = CoinShards::get();
	let sn_list = VNList::get();
	for i in 0usize..size {
		assert!(coin_shards.exist(&senders[i].commitment));
		assert!(coin_shards.exist(&receivers_processed[i].commitment));
		assert_eq!(sn_list[i], senders[i].void_number);
	}
}

fn reclaim_test_helper(iter: usize) {
	// setup
	assert_ok!(Assets::init_asset(Origin::signed(1), 10_000_000));
	assert_eq!(Assets::balance(1), 10_000_000);
	assert_eq!(PoolBalance::get(), 0);

	let hash_param = HashParam::deserialize(HASH_PARAM.data);
	let commit_param = CommitmentParam::deserialize(COMMIT_PARAM.data);

	let size = iter << 1;
	let senders = mint_tokens_helper(size);
	let mut pool = PoolBalance::get();

	let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
	let mut sk = [0u8; 32];

	// load the ZKP keys
	let mut file = File::open("reclaim_pk.bin").unwrap();
	let mut reclaim_pk_bytes: Vec<u8> = vec![];
	file.read_to_end(&mut reclaim_pk_bytes).unwrap();
	let buf: &[u8] = reclaim_pk_bytes.as_ref();
	let pk = Groth16Pk::deserialize_unchecked(buf).unwrap();
	let vk = pk.vk.clone();
	let mut vk_bytes = Vec::new();
	vk.serialize_uncompressed(&mut vk_bytes).unwrap();
	let vk = RECLAIM_PK;
	let vk_checksum = ReclaimZKPKeyChecksum::get();
	assert_eq!(vk.get_checksum(), vk_checksum);

	for i in 0usize..iter {
		let coin_shards = CoinShards::get();
		let sender_1 = senders[i * 2].clone();
		let sender_2 = senders[i * 2 + 1].clone();

		let shard_index_1 = sender_1.commitment[0] as usize;
		let shard_index_2 = sender_2.commitment[0] as usize;

		// generate the merkle trees
		let list_1 = coin_shards.shard[shard_index_1].list.clone();
		let tree_1 = LedgerMerkleTree::new(hash_param.clone(), &list_1).unwrap();
		let merkle_root_1 = tree_1.root();

		let index_1 = list_1
			.iter()
			.position(|x| *x == sender_1.commitment)
			.unwrap();
		let path_1 = tree_1
			.generate_proof(index_1, &sender_1.commitment)
			.unwrap();

		let list_2 = coin_shards.shard[shard_index_2].list.clone();
		let tree_2 = LedgerMerkleTree::new(hash_param.clone(), &list_2).unwrap();
		let merkle_root_2 = tree_2.root();

		let index_2 = list_2
			.iter()
			.position(|x| *x == sender_2.commitment)
			.unwrap();
		let path_2 = tree_2
			.generate_proof(index_2, &sender_2.commitment)
			.unwrap();

		rng.fill_bytes(&mut sk);
		let receiver_full = MantaAssetFullReceiver::sample(&commit_param, &sk, &(), &mut rng);
		let receiver = receiver_full.prepared.process(&10);

		let token_value = sender_1.priv_info.value + sender_2.priv_info.value - receiver.value;

		// generate circuit
		let circuit = ReclaimCircuit {
			commit_param: commit_param.clone(),
			hash_param: hash_param.clone(),

			sender_1: sender_1.clone(),
			sender_membership_1: path_1,
			root_1: merkle_root_1,

			sender_2: sender_2.clone(),
			sender_membership_2: path_2,
			root_2: merkle_root_2,

			receiver: receiver.clone(),

			reclaim_value: token_value,
		};

		// generate ZKP
		let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();
		let mut proof_bytes = [0u8; 192];
		proof.serialize(proof_bytes.as_mut()).unwrap();

		// // ciphertexts
		// let receiver_sk = StaticSecret::new(&mut rng);
		// let receiver_pk = PublicKey::from(&receiver_sk);
		// let receiver_pk_bytes = receiver_pk.to_bytes();
		// let (_sender_pk_bytes, cipher) =
		// 	crypto::manta_dh_enc(&receiver_pk_bytes, receiver.2.value, &mut rng);

		// make the reclaim inputs
		let mut sender_data_1 = [0u8; 96];
		sender_data_1.copy_from_slice(
			[
				sender_1.pub_info.k,
				sender_1.void_number,
				coin_shards.shard[shard_index_1].root,
			]
			.concat()
			.as_ref(),
		);

		let mut sender_data_2 = [0u8; 96];
		sender_data_2.copy_from_slice(
			[
				sender_2.pub_info.k,
				sender_2.void_number,
				coin_shards.shard[shard_index_2].root,
			]
			.concat()
			.as_ref(),
		);

		let mut receiver_data = [0u8; 80];
		receiver_data.copy_from_slice(
			[
				receiver.prepared_data.k.as_ref(),
				receiver.commitment.as_ref(),
				// cipher.as_ref(),
				&[0u8;16],
			]
			.concat()
			.as_ref(),
		);
		// invoke the reclaim event
		assert_ok!(Assets::reclaim(
			Origin::signed(1),
			token_value,
			sender_data_1,
			sender_data_2,
			receiver_data,
			proof_bytes,
		));

		// check the resulting status of the ledger storage
		assert_eq!(TotalSupply::get(), 10_000_000);
		pool -= token_value;
		assert_eq!(PoolBalance::get(), pool);

		let sn_list = VNList::get();
		assert_eq!(sn_list.len(), 2 * (i + 1));
		assert_eq!(sn_list[i * 2], sender_1.void_number);
		assert_eq!(sn_list[i * 2 + 1], sender_2.void_number);
	}
	let enc_value_list = EncValueList::get();
	assert_eq!(enc_value_list.len(), iter);
}
