use crate as pallet_manta_dap;
use crate::{
	coin::*,
	param::{Groth16PK, Groth16VK},
	serdes::*,
	*,
};
use ark_groth16::create_random_proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use frame_support::{assert_noop, assert_ok, parameter_types};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sp_core::H256;
use sp_runtime::{
	testing::Header,
	traits::{BlakeTwo256, IdentityLookup},
};
use std::{fs::File, io::prelude::*};
use x25519_dalek::{PublicKey, StaticSecret};

// use ark_ed_on_bls12_381::Fq;
// use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

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
		MantaModule: pallet_manta_dap::{Module, Call, Storage, Event<T>},
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
		assert_ok!(Assets::init(Origin::signed(1), 100));
		assert_eq!(Assets::balance(1), 100);
		let hash_param = HashParam::deserialize(HASHPARAMBYTES.as_ref());
		let commit_param = CommitmentParam::deserialize(COMPARAMBYTES.as_ref());
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
		assert_ok!(Assets::init(Origin::signed(1), 1000));
		assert_eq!(Assets::balance(1), 1000);
		assert_eq!(PoolBalance::get(), 0);
		let commit_param = CommitmentParam::deserialize(COMPARAMBYTES.as_ref());
		let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
		let mut sk = [0u8; 32];
		rng.fill_bytes(&mut sk);
		let (coin, pub_info, _priv_info) = make_coin(&commit_param, sk, 10, &mut rng);
		let mut mint_data = [0u8; 96];
		mint_data.copy_from_slice(
			[coin.cm_bytes.clone(), pub_info.k, pub_info.s]
				.concat()
				.as_ref(),
		);

		assert_ok!(Assets::mint(Origin::signed(1), 10, mint_data));

		assert_eq!(TotalSupply::get(), 1000);
		assert_eq!(PoolBalance::get(), 10);
		let coin_shards = CoinShards::get();
		assert!(coin_shards.exist(&coin.cm_bytes));
		let sn_list = SNList::get();
		assert_eq!(sn_list.len(), 0);
	});
}

#[test]
fn test_transfer_should_work() {
	new_test_ext().execute_with(|| transfer_test_helper(10));
}

#[ignore]
#[test]
fn test_transfer_should_work_super_long() {
	new_test_ext().execute_with(|| transfer_test_helper(400));
}

// #[test]
// fn test_reclaim_should_work() {
// 	new_test_ext().execute_with(|| reclaim_test_helper(10));
// }

// #[ignore]
// #[test]
// fn test_reclaim_should_work_super_long() {
// 	new_test_ext().execute_with(|| reclaim_test_helper(400));
// }

#[test]
fn issuing_asset_units_to_issuer_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init(Origin::signed(1), 100));
		assert_eq!(Assets::balance(1), 100);
	});
}

#[test]
fn querying_total_supply_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init(Origin::signed(1), 100));
		assert_eq!(Assets::balance(1), 100);
		assert_ok!(Assets::transfer(Origin::signed(1), 2, 50));
		assert_eq!(Assets::balance(1), 50);
		assert_eq!(Assets::balance(2), 50);
		assert_ok!(Assets::transfer(Origin::signed(2), 3, 31));
		assert_eq!(Assets::balance(1), 50);
		assert_eq!(Assets::balance(2), 19);
		assert_eq!(Assets::balance(3), 31);
		assert_eq!(Assets::total_supply(), 100);
	});
}

#[test]
fn transferring_amount_above_available_balance_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init(Origin::signed(1), 100));
		assert_eq!(Assets::balance(1), 100);
		assert_ok!(Assets::transfer(Origin::signed(1), 2, 50));
		assert_eq!(Assets::balance(1), 50);
		assert_eq!(Assets::balance(2), 50);
	});
}

#[test]
fn transferring_amount_more_than_available_balance_should_not_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init(Origin::signed(1), 100));
		assert_eq!(Assets::balance(1), 100);
		assert_ok!(Assets::transfer(Origin::signed(1), 2, 50));
		assert_eq!(Assets::balance(1), 50);
		assert_eq!(Assets::balance(2), 50);
		assert_noop!(
			Assets::transfer(Origin::signed(1), 1, 60),
			Error::<Test>::BalanceLow
		);
	});
}

#[test]
fn transferring_less_than_one_unit_should_not_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init(Origin::signed(1), 100));
		assert_eq!(Assets::balance(1), 100);
		assert_noop!(
			Assets::transfer(Origin::signed(1), 2, 0),
			Error::<Test>::AmountZero
		);
	});
}

#[test]
fn transferring_more_units_than_total_supply_should_not_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init(Origin::signed(1), 100));
		assert_eq!(Assets::balance(1), 100);
		assert_noop!(
			Assets::transfer(Origin::signed(1), 2, 101),
			Error::<Test>::BalanceLow
		);
	});
}

#[test]
fn destroying_asset_balance_with_positive_balance_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init(Origin::signed(1), 100));
		assert_eq!(Assets::balance(1), 100);
	});
}

#[test]
fn cannot_init_twice() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init(Origin::signed(1), 100));
		assert_noop!(
			Assets::init(Origin::signed(1), 100),
			Error::<Test>::AlreadyInitialized
		);
	});
}

fn mint_tokens(size: usize) -> Vec<(MantaCoin, MantaCoinPubInfo, MantaCoinPrivInfo)> {
	let commit_param = CommitmentParam::deserialize(COMPARAMBYTES.as_ref());

	let mut rng = ChaCha20Rng::from_seed([88u8; 32]);
	let mut pool = 0;
	let mut sk = [0u8; 32];

	// sender tokens
	let mut senders = Vec::new();
	for i in 0usize..size {
		// build a sender token
		let token_value = 10 + i as u64;
		rng.fill_bytes(&mut sk);
		let (sender, sender_pub_info, sender_priv_info) =
			make_coin(&commit_param, sk, token_value, &mut rng);

		let mut mint_data = [0u8; 96];
		mint_data.copy_from_slice(
			[
				sender.cm_bytes.clone(),
				sender_pub_info.k,
				sender_pub_info.s,
			]
			.concat()
			.as_ref(),
		);

		// mint a sender token
		assert_ok!(Assets::mint(Origin::signed(1), token_value, mint_data));

		pool += token_value;

		// sanity checks
		assert_eq!(PoolBalance::get(), pool);
		let coin_shards = CoinShards::get();
		assert!(coin_shards.exist(&sender.cm_bytes));
		senders.push((sender, sender_pub_info, sender_priv_info));
	}
	senders
}

fn transfer_test_helper(iter: usize) {
	// setup
	assert_ok!(Assets::init(Origin::signed(1), 10_000_000));
	assert_eq!(Assets::balance(1), 10_000_000);
	assert_eq!(PoolBalance::get(), 0);

	let hash_param = HashParam::deserialize(HASHPARAMBYTES.as_ref());
	let commit_param = CommitmentParam::deserialize(COMPARAMBYTES.as_ref());

	// build ZKP circuit
	let mut file = File::open("transfer_pk.bin").unwrap();
	let mut transfer_key_bytes: Vec<u8> = vec![];
	file.read_to_end(&mut transfer_key_bytes).unwrap();
	let pk = Groth16PK::deserialize_unchecked(transfer_key_bytes.as_ref()).unwrap();
	let vk_bytes = TransferZKPKey::get();
	let vk = Groth16VK::deserialize(vk_bytes.as_ref()).unwrap();
	assert_eq!(pk.vk, vk);

	let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
	let mut sk = [0u8; 32];

	let size = iter << 1;
	let senders = mint_tokens(size);
	let pool = PoolBalance::get();

	let sn_list = SNList::get();
	assert_eq!(sn_list.len(), 0);

	// build receivers
	let mut receivers = Vec::new();
	for i in 0usize..size {
		// build a receiver token
		rng.fill_bytes(&mut sk);
		let (receiver, receiver_pub_info, receiver_priv_info) =
			make_coin(&commit_param, sk, 10 + i as u64, &mut rng);
		receivers.push((receiver, receiver_pub_info, receiver_priv_info));
	}


	// generate and verify transactions
	for i in 0usize..iter {
		let coin_shards = CoinShards::get();
		let sender_1 = senders[i*2].clone();
		let sender_2 = senders[i*2+1].clone();
		let receiver_1 = receivers[i*2+1].clone();
		let receiver_2 = receivers[i*2].clone();

		let shard_index_1 = sender_1.0.cm_bytes[0] as usize;
		let shard_index_2 = sender_2.0.cm_bytes[0] as usize;

		let list_1 = coin_shards.shard[shard_index_1].list.clone();
		let tree_1 = param::LedgerMerkleTree::new(hash_param.clone(), &list_1).unwrap();
		let merkle_root_1 = tree_1.root();

		let index_1 = list_1
			.iter()
			.position(|x| *x == sender_1.0.cm_bytes)
			.unwrap();
		let path_1 = tree_1
			.generate_proof(index_1, &sender_1.0.cm_bytes)
			.unwrap();

		let list_2 = coin_shards.shard[shard_index_2].list.clone();
		let tree_2 = param::LedgerMerkleTree::new(hash_param.clone(), &list_2).unwrap();
		let merkle_root_2 = tree_2.root();

		let index_2 = list_2
			.iter()
			.position(|x| *x == sender_2.0.cm_bytes)
			.unwrap();
		let path_2 = tree_2
			.generate_proof(index_2, &sender_2.0.cm_bytes)
			.unwrap();

		// generate ZKP
		let circuit = crypto::TransferCircuit {
			commit_param: commit_param.clone(),
			hash_param: hash_param.clone(),

			sender_coin_1: sender_1.0.clone(),
			sender_pub_info_1: sender_1.1.clone(),
			sender_priv_info_1: sender_1.2.clone(),
			sender_membership_1: path_1,
			root_1: merkle_root_1,

			sender_coin_2: sender_2.0.clone(),
			sender_pub_info_2: sender_2.1.clone(),
			sender_priv_info_2: sender_2.2.clone(),
			sender_membership_2: path_2,
			root_2: merkle_root_2,

			receiver_coin_1: receiver_1.0.clone(),
			receiver_pub_info_1: receiver_1.1.clone(),
			receiver_value_1: receiver_1.2.value,

			receiver_coin_2: receiver_2.0.clone(),
			receiver_pub_info_2: receiver_2.1.clone(),
			receiver_value_2: receiver_2.2.value,
		};

		let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();
		let mut proof_bytes = [0u8; 192];
		proof.serialize(proof_bytes.as_mut()).unwrap();

		// ciphertexts
		let receiver_sk_1 = StaticSecret::new(&mut rng);
		let receiver_pk_1 = PublicKey::from(&receiver_sk_1);
		let receiver_pk_bytes_1 = receiver_pk_1.to_bytes();
		let receiver_sk_bytes_1 = receiver_sk_1.to_bytes();
		let (sender_pk_bytes_1, cipher_1) =
			crypto::manta_dh_enc(&receiver_pk_bytes_1, receiver_1.2.value, &mut rng);

		let receiver_sk_2 = StaticSecret::new(&mut rng);
		let receiver_pk_2 = PublicKey::from(&receiver_sk_2);
		let receiver_pk_bytes_2 = receiver_pk_2.to_bytes();
		let receiver_sk_bytes_2 = receiver_sk_2.to_bytes();
		let (sender_pk_bytes_2, cipher_2) =
			crypto::manta_dh_enc(&receiver_pk_bytes_2, receiver_2.2.value, &mut rng);

		// make the transfer
		let mut sender_data_1 = [0u8; 64];
		sender_data_1.copy_from_slice(
			[sender_1.1.k, sender_1.2.sn]
				.concat()
				.as_ref(),
		);

		let mut sender_data_2 = [0u8; 64];
		sender_data_2.copy_from_slice(
			[sender_2.1.k, sender_2.2.sn]
				.concat()
				.as_ref(),
		);

		let mut receiver_data_1 = [0u8; 80];
		receiver_data_1.copy_from_slice(
			[
				receiver_1.1.k.as_ref(),
				receiver_1.0.cm_bytes.as_ref(),
				cipher_1.as_ref(),
			]
			.concat()
			.as_ref(),
		);

		let mut receiver_data_2 = [0u8; 80];
		receiver_data_2.copy_from_slice(
			[
				receiver_2.1.k.as_ref(),
				receiver_2.0.cm_bytes.as_ref(),
				cipher_2.as_ref(),
			]
			.concat()
			.as_ref(),
		);

		assert_ok!(Assets::manta_transfer(
			Origin::signed(1),
			coin_shards.shard[shard_index_1].root,
			sender_data_1,
			coin_shards.shard[shard_index_2].root,
			sender_data_2,
			receiver_data_1,
			receiver_data_2,
			proof_bytes,
		));

		let enc_value_list = EncValueList::get();
		assert_eq!(enc_value_list.len(), 2*(i + 1));
		assert_eq!(enc_value_list[2*i], cipher_1);
		assert_eq!(enc_value_list[2*i+1], cipher_2);
		assert_eq!(
			crypto::manta_dh_dec(&cipher_1, &sender_pk_bytes_1, &receiver_sk_bytes_1),
			receiver_1.2.value
		);
		assert_eq!(
			crypto::manta_dh_dec(&cipher_2, &sender_pk_bytes_2, &receiver_sk_bytes_2),
			receiver_2.2.value
		);

		assert_eq!(PoolBalance::get(), pool);
	}

	// check the resulting status of the ledger storage
	assert_eq!(TotalSupply::get(), 10_000_000);
	let coin_shards = CoinShards::get();
	let sn_list = SNList::get();
	for i in 0usize..size {
		assert!(coin_shards.exist(&senders[i].0.cm_bytes));
		assert!(coin_shards.exist(&receivers[i].0.cm_bytes));
		assert_eq!(sn_list[i], senders[i].2.sn);
	}
}

// fn reclaim_test_helper(iter: usize) {
// 	// setup
// 	assert_ok!(Assets::init(Origin::signed(1), 10_000_000));
// 	assert_eq!(Assets::balance(1), 10_000_000);
// 	assert_eq!(PoolBalance::get(), 0);

// 	let hash_param = HashParam::deserialize(HASHPARAMBYTES.as_ref());
// 	let commit_param = CommitmentParam::deserialize(COMPARAMBYTES.as_ref());


// 	let size = iter << 1;
// 	let senders = mint_tokens(size);
// 	let pool = PoolBalance::get();

// 	let mut rng = ChaCha20Rng::from_seed([3u8; 32]);

// 	// build ZKP circuit
// 	let mut file = File::open("reclaim_pk.bin").unwrap();
// 	let mut reclaim_pk_bytes: Vec<u8> = vec![];
// 	file.read_to_end(&mut reclaim_pk_bytes).unwrap();
// 	let pk = Groth16PK::deserialize_uncompressed(reclaim_pk_bytes.as_ref()).unwrap();
// 	let vk_bytes = ReclaimZKPKey::get();
// 	let vk = Groth16VK::deserialize(vk_bytes.as_ref()).unwrap();
// 	assert_eq!(pk.vk, vk);

// 	// generate and verify transactions
// 	let coin_shards = CoinShards::get();
// 	for i in 0usize..size {
// 		let token_value = 10 + i as u64;
// 		let shard_index = senders[i].0.cm_bytes[0] as usize;
// 		// generate ZKP
// 		let circuit = crypto::ReclaimCircuit {
// 			commit_param: commit_param.clone(),
// 			hash_param: hash_param.clone(),
// 			sender_coin: senders[i].0.clone(),
// 			sender_pub_info: senders[i].1.clone(),
// 			sender_priv_info: senders[i].2.clone(),
// 			value: token_value,
// 			list: coin_shards.shard[shard_index].list.clone(),
// 		};

// 		let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();
// 		let mut proof_bytes = [0u8; 192];
// 		proof.serialize(proof_bytes.as_mut()).unwrap();

// 		let mut sender_data = [0u8; 64];
// 		sender_data.copy_from_slice([senders[i].1.k, senders[i].2.sn].concat().as_ref());

// 		// make the reclaim
// 		assert_ok!(Assets::reclaim(
// 			Origin::signed(1),
// 			token_value,
// 			coin_shards.shard[shard_index].root,
// 			sender_data,
// 			proof_bytes,
// 		));

// 		// check the resulting status of the ledger storage
// 		assert_eq!(TotalSupply::get(), 10_000_000);
// 		pool -= token_value;
// 		assert_eq!(PoolBalance::get(), pool);

// 		let sn_list = SNList::get();
// 		assert_eq!(sn_list.len(), i + 1);
// 		assert_eq!(sn_list[i], senders[i].2.sn);
// 	}
// 	let enc_value_list = EncValueList::get();
// 	assert_eq!(enc_value_list.len(), 0);
// }
