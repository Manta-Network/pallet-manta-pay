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
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::{RngCore, SeedableRng};
use frame_support::{assert_noop, assert_ok, parameter_types};
use manta_asset::*;
use manta_crypto::*;
use rand_chacha::ChaCha20Rng;
use sp_core::H256;
use sp_runtime::{
	testing::Header,
	traits::{BlakeTwo256, IdentityLookup},
};
use std::{boxed::Box, fs::File, io::prelude::*, string::String};

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
	type WeightInfo = ();
}
type Assets = Module<Test>;

fn new_test_ext() -> sp_io::TestExternalities {
	frame_system::GenesisConfig::default()
		.build_storage::<Test>()
		.unwrap()
		.into()
}

// todo: write must-fail tests for cross-asset-id tests

// Misc tests:

#[test]
fn test_constants_should_work() {
	new_test_ext().execute_with(|| {
		initialize_test(100);
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
fn issuing_asset_units_to_issuer_should_work() {
	new_test_ext().execute_with(|| {
		initialize_test(100);
	});
}

#[test]
fn querying_total_supply_should_work() {
	new_test_ext().execute_with(|| {
		initialize_test(100);
		assert_ok!(Assets::transfer_asset(Origin::signed(1), 2, TEST_ASSET, 50));
		assert_eq!(Assets::balance(1, TEST_ASSET), 50);
		assert_eq!(Assets::balance(2, TEST_ASSET), 50);
		assert_ok!(Assets::transfer_asset(Origin::signed(2), 3, TEST_ASSET, 31));
		assert_eq!(Assets::balance(1, TEST_ASSET), 50);
		assert_eq!(Assets::balance(2, TEST_ASSET), 19);
		assert_eq!(Assets::balance(3, TEST_ASSET), 31);
		assert_eq!(Assets::total_supply(TEST_ASSET), 100);
	});
}

#[test]
fn destroying_asset_balance_with_positive_balance_should_work() {
	new_test_ext().execute_with(|| {
		initialize_test(100);
	});
}

// Init tests:

#[test]
fn cannot_init_twice() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init_asset(Origin::signed(1), TEST_ASSET, 100));
		assert_noop!(
			Assets::init_asset(Origin::signed(1), TEST_ASSET, 100),
			Error::<Test>::AlreadyInitialized
		);
	});
}

// Mint tests:

#[test]
fn test_mint_should_work() {
	new_test_ext().execute_with(|| {
		initialize_test(1000);

		let commit_param = CommitmentParam::deserialize(COMMIT_PARAM.data);
		let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
		let mut sk = [0u8; 32];
		rng.fill_bytes(&mut sk);
		let asset = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &10, &mut rng);

		let payload = generate_mint_payload(&asset);
		assert_ok!(Assets::mint_private_asset(Origin::signed(1), payload));

		assert_eq!(TotalSupply::get(TEST_ASSET), 1000);
		assert_eq!(PoolBalance::get(TEST_ASSET), 10);
		let coin_shards = CoinShards::get();
		assert!(coin_shards.exist(&asset.commitment));
		let vn_list = VNList::get();
		assert_eq!(vn_list.len(), 0);
	});
}

#[test]
fn mint_without_init_should_not_work() {
	new_test_ext().execute_with(|| {
		let payload = generate_mint_payload_helper(100);

		assert_noop!(
			Assets::mint_private_asset(Origin::signed(1), payload),
			Error::<Test>::BasecoinNotInit
		);
	});
}

#[test]
fn mint_zero_amount_should_not_work() {
	new_test_ext().execute_with(|| {
		initialize_test(100);

		let payload = generate_mint_payload_helper(0);

		assert_noop!(
			Assets::mint_private_asset(Origin::signed(1), payload),
			Error::<Test>::AmountZero
		);
	});
}

#[test]
fn mint_with_insufficient_origin_balance_should_not_work() {
	new_test_ext().execute_with(|| {
		initialize_test(100);

		assert_ok!(Assets::transfer_asset(Origin::signed(1), 2, TEST_ASSET, 99));
		assert_eq!(Assets::balance(1, TEST_ASSET), 1);
		assert_eq!(Assets::balance(2, TEST_ASSET), 99);

		let payload = generate_mint_payload_helper(50);

		assert_noop!(
			Assets::mint_private_asset(Origin::signed(1), payload),
			Error::<Test>::BalanceLow
		);
	});
}

#[test]
fn mint_with_existing_coin_should_not_work() {
	new_test_ext().execute_with(|| {
		initialize_test(100);

		let payload = generate_mint_payload_helper(50);
		assert_ok!(Assets::mint_private_asset(Origin::signed(1), payload));

		assert_noop!(
			Assets::mint_private_asset(Origin::signed(1), payload),
			Error::<Test>::MantaCoinExist
		);
	});
}

#[test]
fn mint_with_invalid_commitment_should_not_work() {
	new_test_ext().execute_with(|| {
		initialize_test(100);

		let commit_param = CommitmentParam::deserialize(
			Parameter {
				data: &[0u8; 81664],
			}
			.data,
		);
		let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
		let mut sk = [0u8; 32];
		rng.fill_bytes(&mut sk);
		let asset = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &50, &mut rng);
		let payload = generate_mint_payload(&asset);

		assert_noop!(
			Assets::mint_private_asset(Origin::signed(1), payload),
			Error::<Test>::MintFail
		);
	});
}

#[test]
fn mint_with_hash_param_mismatch_should_not_work() {
	new_test_ext().execute_with(|| {
		initialize_test(100);

		let payload = generate_mint_payload_helper(50);
		assert_ok!(Assets::mint_private_asset(Origin::signed(1), payload));

		HashParamChecksum::put([3u8; 32]);

		assert_noop!(
			Assets::mint_private_asset(Origin::signed(1), payload),
			Error::<Test>::MintFail
		);
	});
}

#[test]
fn mint_with_commit_param_mismatch_should_not_work() {
	new_test_ext().execute_with(|| {
		initialize_test(100);

		let payload = generate_mint_payload_helper(50);
		assert_ok!(Assets::mint_private_asset(Origin::signed(1), payload));

		CommitParamChecksum::put([3u8; 32]);

		assert_noop!(
			Assets::mint_private_asset(Origin::signed(1), payload),
			Error::<Test>::MintFail
		);
	});
}

// Transfer tests:

#[test]
fn test_transfer_should_work() {
	new_test_ext().execute_with(|| transfer_test_helper(1));
}

#[ignore]
#[test]
fn test_transfer_should_work_super_long() {
	new_test_ext().execute_with(|| transfer_test_helper(400));
}

#[test]
fn transferring_amount_below_available_balance_should_work() {
	new_test_ext().execute_with(|| {
		initialize_test(100);
		assert_ok!(Assets::transfer_asset(Origin::signed(1), 2, TEST_ASSET, 50));
		assert_eq!(Assets::balance(1, TEST_ASSET), 50);
		assert_eq!(Assets::balance(2, TEST_ASSET), 50);
	});
}

#[test]
fn transferring_amount_more_than_available_balance_should_not_work() {
	new_test_ext().execute_with(|| {
		initialize_test(100);
		assert_ok!(Assets::transfer_asset(Origin::signed(1), 2, TEST_ASSET, 50));
		assert_eq!(Assets::balance(1, TEST_ASSET), 50);
		assert_eq!(Assets::balance(2, TEST_ASSET), 50);
		assert_noop!(
			Assets::transfer_asset(Origin::signed(1), 1, TEST_ASSET, 60),
			Error::<Test>::BalanceLow
		);
	});
}

#[test]
fn transferring_less_than_one_unit_should_not_work() {
	new_test_ext().execute_with(|| {
		initialize_test(100);
		assert_noop!(
			Assets::transfer_asset(Origin::signed(1), 2, TEST_ASSET, 0),
			Error::<Test>::AmountZero
		);
	});
}

#[test]
fn transferring_more_units_than_total_supply_should_not_work() {
	new_test_ext().execute_with(|| {
		initialize_test(100);
		assert_noop!(
			Assets::transfer_asset(Origin::signed(1), 2, TEST_ASSET, 101),
			Error::<Test>::BalanceLow
		);
	});
}

#[test]
fn transferring_with_hash_param_mismatch_should_not_work() {
	new_test_ext().execute_with(|| {
		initialize_test(10_000_000);

		let payload = [0u8; 608];
		HashParamChecksum::put([3u8; 32]);

		// invoke the transfer event
		assert_noop!(
			Assets::private_transfer(Origin::signed(1), payload),
			Error::<Test>::MintFail
		);
	});
}

#[test]
fn transferring_without_init_should_not_work() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			Assets::transfer_asset(Origin::signed(1), 2, TEST_ASSET, 101),
			Error::<Test>::BasecoinNotInit
		);
	});
}

#[test]
fn transferring_spent_coin_should_not_work_sender_1() {
	new_test_ext().execute_with(|| {
		initialize_test(10_000_000);

		let (commit_param, hash_param, pk, mut sk, mut rng) = setup_params_for_transferring();
		let iter = 1;
		let size = iter << 1;
		let senders = mint_tokens_helper(size);

		let (_, receivers_processed) = build_receivers(&commit_param, &mut sk, &mut rng, size);

		for i in 0usize..iter {
			let payload = prepare_private_transfer_payload(
				&senders,
				&commit_param,
				&hash_param,
				&pk,
				&receivers_processed,
				&mut rng,
				i,
			);

			assert_ok!(Assets::private_transfer(Origin::signed(1), payload));

			assert_noop!(
				Assets::private_transfer(Origin::signed(1), payload),
				Error::<Test>::MantaCoinSpent
			);
		}
	});
}

#[test]
fn transferring_existing_coins_should_not_work() {
	new_test_ext().execute_with(|| {
		initialize_test(10_000_000);

		let (commit_param, hash_param, pk, mut sk, mut rng) = setup_params_for_transferring();

		let iter = 2;
		let size = iter << 1;
		let senders = mint_tokens_helper(size);

		let (_, receivers_processed) = build_receivers(&commit_param, &mut sk, &mut rng, size);

		for i in 0usize..iter {
			let mut coin_shards = CoinShards::get();

			// extract the receivers
			let receiver_1 = receivers_processed[i * 2 + 1].clone();
			let receiver_2 = receivers_processed[i * 2].clone();

			let payload = prepare_private_transfer_payload(
				&senders,
				&commit_param,
				&hash_param,
				&pk,
				&receivers_processed,
				&mut rng,
				i,
			);

			if i == 0 {
				coin_shards.update(&receiver_1.commitment, hash_param.clone());
				CoinShards::put(coin_shards);

				assert_noop!(
					Assets::private_transfer(Origin::signed(1), payload),
					Error::<Test>::MantaCoinExist
				);
			} else {
				coin_shards.update(&receiver_2.commitment, hash_param.clone());
				CoinShards::put(coin_shards);

				assert_noop!(
					Assets::private_transfer(Origin::signed(1), payload),
					Error::<Test>::MantaCoinExist
				);
			}
		}
	});
}

#[test]
fn transferring_spent_coin_should_not_work_sender_2() {
	new_test_ext().execute_with(|| {
		initialize_test(10_000_000);

		let (commit_param, hash_param, pk, mut sk, mut rng) = setup_params_for_transferring();

		let size = 4;
		let senders = mint_tokens_helper(size);

		let (_, receivers_processed) = build_receivers(&commit_param, &mut sk, &mut rng, size);

		let mut coin_shards = CoinShards::get();

		let payload = prepare_private_transfer_payload(
			&senders,
			&commit_param,
			&hash_param,
			&pk,
			&receivers_processed,
			&mut rng,
			0,
		);

		assert_ok!(Assets::private_transfer(Origin::signed(1), payload));

		// extract the receivers
		let receiver_1 = receivers_processed[0].clone();
		let receiver_2 = receivers_processed[2].clone();

		coin_shards.update(&receiver_1.commitment, hash_param.clone());
		coin_shards.update(&receiver_2.commitment, hash_param.clone());

		// build sender meta data
		let sender_1 = senders[2].clone();
		let sender_2 = senders[0].clone();
		let shard_index_1 = sender_1.commitment[0] as usize;
		let shard_index_2 = sender_2.commitment[0] as usize;
		let list_1 = coin_shards.shard[shard_index_1].list.clone();
		let sender_1 = SenderMetaData::build(hash_param.clone(), sender_1, &list_1);
		let list_2 = coin_shards.shard[shard_index_2].list.clone();
		let sender_2 = SenderMetaData::build(hash_param.clone(), sender_2, &list_2);

		let payload = generate_private_transfer_payload(
			commit_param.clone(),
			hash_param.clone(),
			&pk,
			sender_1,
			sender_2,
			receiver_1,
			receiver_2,
			&mut rng,
		);

		assert_noop!(
			Assets::private_transfer(Origin::signed(1), payload),
			Error::<Test>::MantaCoinSpent
		);
	});
}

#[test]
fn transferring_with_invalid_ledger_state_should_not_work() {
	new_test_ext().execute_with(|| {
		initialize_test(10_000_000);

		let (commit_param, hash_param, pk, mut sk, mut rng) = setup_params_for_transferring();

		let size = 4;
		let senders = mint_tokens_helper(size);

		let (_, receivers_processed) = build_receivers(&commit_param, &mut sk, &mut rng, size);

		let payload = prepare_private_transfer_payload(
			&senders,
			&commit_param,
			&hash_param,
			&pk,
			&receivers_processed,
			&mut rng,
			0,
		);

		let mut data = PrivateTransferData::deserialize(payload.as_ref());
		data.sender_1.root = [5u8; 32];
		let mut payload_with_bad_root = [0u8; PRIVATE_TRANSFER_PAYLOAD_SIZE];
		data.serialize(payload_with_bad_root.as_mut());

		assert_noop!(
			Assets::private_transfer(Origin::signed(1), payload_with_bad_root),
			Error::<Test>::InvalidLedgerState
		);

		let payload = prepare_private_transfer_payload(
			&senders,
			&commit_param,
			&hash_param,
			&pk,
			&receivers_processed,
			&mut rng,
			1,
		);

		let mut data = PrivateTransferData::deserialize(payload.as_ref());
		data.sender_2.root = [5u8; 32];
		let mut payload_with_bad_root = [0u8; PRIVATE_TRANSFER_PAYLOAD_SIZE];
		data.serialize(payload_with_bad_root.as_mut());

		assert_noop!(
			Assets::private_transfer(Origin::signed(1), payload_with_bad_root),
			Error::<Test>::InvalidLedgerState
		);
	});
}

#[test]
fn transferring_with_invalid_zkp_param_should_not_work() {
	new_test_ext().execute_with(|| {
		initialize_test(10_000_000);

		let (commit_param, hash_param, pk, mut sk, mut rng) = setup_params_for_transferring();

		let iter = 1;
		let size = iter << 1;
		let senders = mint_tokens_helper(size);

		let (_, receivers_processed) = build_receivers(&commit_param, &mut sk, &mut rng, size);

		for i in 0usize..iter {
			let payload = prepare_private_transfer_payload(
				&senders,
				&commit_param,
				&hash_param,
				&pk,
				&receivers_processed,
				&mut rng,
				i,
			);

			let transfer_vk = VerificationKey { data: &[0u8; 2312] };
			let transfer_key_digest = transfer_vk.get_checksum();
			TransferZKPKeyChecksum::put(transfer_key_digest);
			assert_noop!(
				Assets::private_transfer(Origin::signed(1), payload),
				Error::<Test>::ZkpParamFail
			);
		}
	});
}

#[test]
fn transferring_with_zkp_verification_fail_should_not_work() {
	new_test_ext().execute_with(|| {
		initialize_test(10_000_000);

		let (commit_param, hash_param, pk, mut sk, mut rng) = setup_params_for_transferring();

		let iter = 1;
		let size = iter << 1;
		let senders = mint_tokens_helper(size);

		let (_, receivers_processed) = build_receivers(&commit_param, &mut sk, &mut rng, size);

		for i in 0usize..iter {
			let payload = prepare_private_transfer_payload(
				&senders,
				&commit_param,
				&hash_param,
				&pk,
				&receivers_processed,
				&mut rng,
				i,
			);

			let mut data = PrivateTransferData::deserialize(payload.as_ref());
			data.proof = [0u8; 192];
			let mut payload_with_bad_proof = [0u8; PRIVATE_TRANSFER_PAYLOAD_SIZE];
			data.serialize(payload_with_bad_proof.as_mut());

			assert_noop!(
				Assets::private_transfer(Origin::signed(1), payload_with_bad_proof),
				Error::<Test>::ZkpVerificationFail
			);
		}
	});
}

// Reclaim tests:

#[test]
fn test_reclaim_should_work() {
	new_test_ext().execute_with(|| reclaim_test_helper(1));
}

#[ignore]
#[test]
fn test_reclaim_should_work_super_long() {
	new_test_ext().execute_with(|| reclaim_test_helper(400));
}

#[test]
fn reclaim_without_init_should_not_work() {
	new_test_ext().execute_with(|| {
		let payload = [0u8; RECLAIM_PAYLOAD_SIZE];

		assert_noop!(
			Assets::reclaim(Origin::signed(1), payload),
			Error::<Test>::BasecoinNotInit
		);
	});
}

#[test]
fn reclaim_with_hash_param_mismatch_should_not_work() {
	new_test_ext().execute_with(|| {
		initialize_test(10_000_000);

		let payload = [0u8; RECLAIM_PAYLOAD_SIZE];
		HashParamChecksum::put([3u8; 32]);

		// invoke the transfer event
		assert_noop!(
			Assets::reclaim(Origin::signed(1), payload),
			Error::<Test>::MintFail
		);
	});
}

#[test]
fn reclaim_with_overdrawn_pool_should_not_work() {
	new_test_ext().execute_with(|| {
		initialize_test(10_000_000);

		let (commit_param, hash_param, pk, mut sk, mut rng) = setup_params_for_reclaim();

		let iter = 1;
		let size = iter << 1;
		let senders = mint_tokens_helper(size);

		for i in 0usize..iter {
			let (payload, _, _, _) = prepare_reclaim_payload(
				&senders,
				&commit_param,
				&hash_param,
				&pk,
				&mut sk,
				&mut rng,
				i,
			);

			assert_ok!(Assets::reclaim(Origin::signed(1), payload));

			assert_noop!(
				Assets::reclaim(Origin::signed(1), payload),
				Error::<Test>::PoolOverdrawn
			);
		}
	});
}

// Helper functions:

fn mint_tokens_helper(size: usize) -> Vec<MantaAsset> {
	let commit_param = CommitmentParam::deserialize(COMMIT_PARAM.data);

	let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
	let mut pool = 0;
	let mut sk = [0u8; 32];

	// sender tokens
	let mut senders = Vec::new();
	for i in 0usize..size {
		// build a sender token
		let token_value = 10 + i as u64;
		rng.fill_bytes(&mut sk);
		let asset = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &token_value, &mut rng);
		let payload = generate_mint_payload(&asset);

		// mint a sender token
		assert_ok!(Assets::mint_private_asset(Origin::signed(1), payload));

		pool += token_value;

		// sanity checks
		assert_eq!(PoolBalance::get(TEST_ASSET), pool);
		let coin_shards = CoinShards::get();
		assert!(coin_shards.exist(&asset.commitment));
		senders.push(asset);
	}
	senders
}

fn generate_mint_payload_helper(value: u64) -> [u8; MINT_PAYLOAD_SIZE] {
	let commit_param = CommitmentParam::deserialize(COMMIT_PARAM.data);
	let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
	let mut sk = [0u8; 32];
	rng.fill_bytes(&mut sk);
	let asset = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &value, &mut rng);
	generate_mint_payload(&asset)
}

fn transfer_test_helper(iter: usize) {
	initialize_test(10_000_000);

	let (commit_param, hash_param, pk, mut sk, mut rng) = setup_params_for_transferring();

	let size = iter << 1;
	let senders = mint_tokens_helper(size);
	let pool = PoolBalance::get(TEST_ASSET);

	let (receivers_full, receivers_processed) =
		build_receivers(&commit_param, &mut sk, &mut rng, size);

	for i in 0usize..iter {
		let receiver_1 = receivers_processed[i * 2 + 1].clone();
		let receiver_2 = receivers_processed[i * 2].clone();

		let payload = prepare_private_transfer_payload(
			&senders,
			&commit_param,
			&hash_param,
			&pk,
			&receivers_processed,
			&mut rng,
			i,
		);

		// invoke the transfer event
		assert_ok!(Assets::private_transfer(Origin::signed(1), payload));

		// check the ciphertexts
		let enc_value_list = EncValueList::get();
		assert_eq!(enc_value_list.len(), 2 * (i + 1));
		assert_eq!(enc_value_list[2 * i], receiver_1.ciphertext);
		assert_eq!(enc_value_list[2 * i + 1], receiver_2.ciphertext);

		let mut ciphertext_1 = [0u8; 48];
		ciphertext_1[0..16].copy_from_slice(receiver_1.ciphertext.as_ref());
		ciphertext_1[16..48].copy_from_slice(receiver_1.sender_pk.as_ref());
		let sk_1 = receivers_full[i * 2 + 1].spend.ecsk.clone();
		assert_eq!(
			<MantaCrypto as Ecies>::decrypt(&sk_1, &ciphertext_1),
			receiver_1.value
		);

		let mut ciphertext_2 = [0u8; 48];
		ciphertext_2[0..16].copy_from_slice(receiver_2.ciphertext.as_ref());
		ciphertext_2[16..48].copy_from_slice(receiver_2.sender_pk.as_ref());
		let sk_2 = receivers_full[i * 2].spend.ecsk.clone();
		assert_eq!(
			<MantaCrypto as Ecies>::decrypt(&sk_2, &ciphertext_2),
			receiver_2.value
		);
		assert_eq!(PoolBalance::get(TEST_ASSET), pool);
	}

	// check the resulting status of the ledger storage
	assert_eq!(TotalSupply::get(TEST_ASSET), 10_000_000);
	let coin_shards = CoinShards::get();
	let vn_list = VNList::get();
	for i in 0usize..size {
		assert!(coin_shards.exist(&senders[i].commitment));
		assert!(coin_shards.exist(&receivers_processed[i].commitment));
		assert_eq!(vn_list[i], senders[i].void_number);
	}
}

fn reclaim_test_helper(iter: usize) {
	initialize_test(10_000_000);

	let (commit_param, hash_param, pk, mut sk, mut rng) = setup_params_for_reclaim();

	let size = iter << 1;
	let senders = mint_tokens_helper(size);
	let mut pool = PoolBalance::get(TEST_ASSET);

	for i in 0usize..iter {
		let (payload, sender_1, sender_2, reclaim_value) = prepare_reclaim_payload(
			&senders,
			&commit_param,
			&hash_param,
			&pk,
			&mut sk,
			&mut rng,
			i,
		);

		// invoke the reclaim event
		assert_ok!(Assets::reclaim(Origin::signed(1), payload));

		// check the resulting status of the ledger storage
		assert_eq!(TotalSupply::get(TEST_ASSET), 10_000_000);
		pool -= reclaim_value;
		assert_eq!(PoolBalance::get(TEST_ASSET), pool);

		let vn_list = VNList::get();
		assert_eq!(vn_list.len(), 2 * (i + 1));
		assert_eq!(vn_list[i * 2], sender_1.asset.void_number);
		assert_eq!(vn_list[i * 2 + 1], sender_2.asset.void_number);
	}
	let enc_value_list = EncValueList::get();
	assert_eq!(enc_value_list.len(), iter);
}

fn prepare_private_transfer_payload(
	senders: &Vec<MantaAsset>,
	commit_param: &CommitmentParam,
	hash_param: &HashParam,
	pk: &Groth16Pk,
	receivers_processed: &Vec<MantaAssetProcessedReceiver>,
	rng: &mut ChaCha20Rng,
	idx: usize,
) -> [u8; PRIVATE_TRANSFER_PAYLOAD_SIZE] {
	// build sender mata data
	let (sender_1, sender_2) = build_sender_meta_data(&senders, &hash_param, idx);

	// extract the receivers
	let receiver_1 = receivers_processed[idx * 2 + 1].clone();
	let receiver_2 = receivers_processed[idx * 2].clone();

	// form the transaction payload
	generate_private_transfer_payload(
		commit_param.clone(),
		hash_param.clone(),
		&pk,
		sender_1,
		sender_2,
		receiver_1,
		receiver_2,
		rng,
	)
}

fn prepare_reclaim_payload(
	senders: &Vec<MantaAsset>,
	commit_param: &CommitmentParam,
	hash_param: &HashParam,
	pk: &Groth16Pk,
	sk: &mut [u8; 32],
	rng: &mut ChaCha20Rng,
	idx: usize,
) -> (
	[u8; RECLAIM_PAYLOAD_SIZE],
	zkp::SenderMetaData,
	zkp::SenderMetaData,
	u64,
) {
	// build sender mata data
	let (sender_1, sender_2) = build_sender_meta_data(&senders, &hash_param, idx);

	rng.fill_bytes(&mut sk[..]);
	let receiver_full = MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &(), rng);
	let receiver = receiver_full.prepared.process(&10, rng);

	let reclaim_value =
		sender_1.asset.priv_info.value + sender_2.asset.priv_info.value - receiver.value;

	// form the transaction payload
	let payload = generate_reclaim_payload(
		commit_param.clone(),
		hash_param.clone(),
		&pk,
		sender_1.clone(),
		sender_2.clone(),
		receiver,
		reclaim_value,
		rng,
	);

	(payload, sender_1, sender_2, reclaim_value)
}

fn load_zkp_keys(file_name: &str) -> Groth16Pk {
	let mut file = File::open(file_name).unwrap();
	let mut transfer_key_bytes: Vec<u8> = vec![];
	file.read_to_end(&mut transfer_key_bytes).unwrap();
	let buf: &[u8] = transfer_key_bytes.as_ref();
	Groth16Pk::deserialize_unchecked(buf).unwrap()
}

fn initialize_test(amount: u64) {
	assert_ok!(Assets::init_asset(Origin::signed(1), TEST_ASSET, amount));
	assert_eq!(Assets::balance(1, TEST_ASSET), amount);
	assert_eq!(PoolBalance::get(TEST_ASSET), 0);
}

fn build_sender_meta_data(
	senders: &Vec<MantaAsset>,
	hash_param: &HashParam,
	idx: usize,
) -> (zkp::SenderMetaData, zkp::SenderMetaData) {
	let coin_shards = CoinShards::get();

	let sender_1 = senders[idx * 2].clone();
	let sender_2 = senders[idx * 2 + 1].clone();
	let shard_index_1 = sender_1.commitment[0] as usize;
	let shard_index_2 = sender_2.commitment[0] as usize;
	let list_1 = coin_shards.shard[shard_index_1].list.clone();
	let out_sender_1 = SenderMetaData::build(hash_param.clone(), sender_1, &list_1).into();
	let list_2 = coin_shards.shard[shard_index_2].list.clone();
	let out_sender_2 = SenderMetaData::build(hash_param.clone(), sender_2, &list_2);

	(out_sender_1, out_sender_2)
}

fn build_receivers(
	commit_param: &CommitmentParam,
	sk: &mut [u8; 32],
	rng: &mut ChaCha20Rng,
	size: usize,
) -> (
	Vec<MantaAssetFullReceiver>,
	Vec<MantaAssetProcessedReceiver>,
) {
	// build receivers
	let mut receivers_full = Vec::new();
	let mut receivers_processed = Vec::new();
	for i in 0usize..size {
		// build a receiver token
		rng.fill_bytes(&mut sk[..]);
		let receiver_full =
			MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &(), rng);
		let receiver = receiver_full.prepared.process(&(i as u64 + 10), rng);
		receivers_full.push(receiver_full);
		receivers_processed.push(receiver);
	}

	(receivers_full, receivers_processed)
}

fn setup_params(file_name: &str) -> (CommitmentParam, HashParam, Groth16Pk, [u8; 32], ChaCha20Rng) {
	let hash_param = HashParam::deserialize(HASH_PARAM.data);
	let commit_param = CommitmentParam::deserialize(COMMIT_PARAM.data);

	let pk = load_zkp_keys(file_name);
	let vk_checksum = TransferZKPKeyChecksum::get();
	assert_eq!(TRANSFER_PK.get_checksum(), vk_checksum);

	let rng = ChaCha20Rng::from_seed([3u8; 32]);
	let sk = [0u8; 32];

	let vn_list = VNList::get();
	assert_eq!(vn_list.len(), 0);

	(commit_param, hash_param, pk, sk, rng)
}

fn setup_params_for_transferring() -> (CommitmentParam, HashParam, Groth16Pk, [u8; 32], ChaCha20Rng)
{
	let vk_checksum = TransferZKPKeyChecksum::get();
	assert_eq!(TRANSFER_PK.get_checksum(), vk_checksum);

	setup_params("transfer_pk.bin")
}

fn setup_params_for_reclaim() -> (CommitmentParam, HashParam, Groth16Pk, [u8; 32], ChaCha20Rng) {
	let vk_checksum = ReclaimZKPKeyChecksum::get();
	assert_eq!(RECLAIM_PK.get_checksum(), vk_checksum);

	setup_params("reclaim_pk.bin")
}
