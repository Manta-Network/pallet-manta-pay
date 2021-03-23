use crate as pallet_manta_dap;
use crate::{dh::*, manta_token::*, param::*, reclaim::*, serdes::*, transfer::*, *};
use ark_ed_on_bls12_381::Fq;
use ark_groth16::create_random_proof;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
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
		let commit_param = MantaCoinCommitmentParam::deserialize(COMPARAMBYTES.as_ref());
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
		let commit_param = MantaCoinCommitmentParam::deserialize(COMPARAMBYTES.as_ref());
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
		let coin_list = CoinList::get();
		assert_eq!(coin_list.len(), 1);
		assert_eq!(coin_list[0].as_ref(), coin.cm_bytes);
		let sn_list = SNList::get();
		assert_eq!(sn_list.len(), 0);
	});
}

// #[ignore]
#[test]
fn test_transfer_should_work() {
	new_test_ext().execute_with(|| {
		// setup
		assert_ok!(Assets::init(Origin::signed(1), 100000));
		assert_eq!(Assets::balance(1), 100000);
		assert_eq!(PoolBalance::get(), 0);

		let hash_param = HashParam::deserialize(HASHPARAMBYTES.as_ref());
		let commit_param = MantaCoinCommitmentParam::deserialize(COMPARAMBYTES.as_ref());

		let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
		let mut pool = 0;
		let size = 10usize;

		// sender tokens
		let mut senders = Vec::new();
		for i in 0usize..size {
			// build a sender token
			let mut sk = [0u8; 32];
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
			let coin_list = CoinList::get();
			assert_eq!(coin_list.len(), i + 1);
			assert_eq!(coin_list[i], sender.cm_bytes);
			let sn_list = SNList::get();
			assert_eq!(sn_list.len(), 0);

			senders.push((sender, sender_pub_info, sender_priv_info));
		}

		// build receivers
		let mut receivers = Vec::new();
		for i in 0usize..size {
			// build a receiver token
			let mut sk = [0u8; 32];
			rng.fill_bytes(&mut sk);
			let (receiver, receiver_pub_info, receiver_priv_info) =
				make_coin(&commit_param, sk, 10 + i as u64, &mut rng);
			receivers.push((receiver, receiver_pub_info, receiver_priv_info));
		}

		// build ZKP circuit
		let mut file = File::open("transfer_pk.bin").unwrap();
		let mut transfer_key_bytes: Vec<u8> = vec![];
		file.read_to_end(&mut transfer_key_bytes).unwrap();
		let pk = Groth16PK::deserialize_uncompressed(transfer_key_bytes.as_ref()).unwrap();

		// generate and verify transactions
		for i in 0usize..size {
			let coin_list = CoinList::get();
			let root = LedgerState::get();
			// generate ZKP
			let circuit = TransferCircuit {
				commit_param: commit_param.clone(),
				hash_param: hash_param.clone(),
				sender_coin: senders[i].0.clone(),
				sender_pub_info: senders[i].1.clone(),
				sender_priv_info: senders[i].2.clone(),
				receiver_coin: receivers[i].0.clone(),
				receiver_pub_info: receivers[i].1.clone(),
				list: coin_list.to_vec(),
			};

			let sanity_cs = ConstraintSystem::<Fq>::new_ref();
			circuit
				.clone()
				.generate_constraints(sanity_cs.clone())
				.unwrap();
			assert!(sanity_cs.is_satisfied().unwrap());

			let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();
			let vk_bytes = TransferZKPKey::get();
			let vk = Groth16VK::deserialize(vk_bytes.as_ref()).unwrap();
			assert_eq!(pk.vk, vk);

			let mut proof_bytes = [0u8; 192];
			proof.serialize(proof_bytes.as_mut()).unwrap();

			// make the transfer
			let receiver_sk = StaticSecret::new(&mut rng);
			let receiver_pk = PublicKey::from(&receiver_sk);
			let receiver_pk_bytes = receiver_pk.to_bytes();
			let receiver_sk_bytes = receiver_sk.to_bytes();
			let (sender_pk_bytes, cipher) =
				manta_dh_enc(&receiver_pk_bytes, 10 + i as u64, &mut rng);

			let mut sender_data = [0u8; 64];
			sender_data.copy_from_slice([senders[i].1.k, senders[i].2.sn].concat().as_ref());

			let mut receiver_data = [0u8; 80];
			receiver_data.copy_from_slice(
				[
					receivers[i].1.k.as_ref(),
					receivers[i].0.cm_bytes.as_ref(),
					cipher.as_ref(),
				]
				.concat()
				.as_ref(),
			);

			assert_ok!(Assets::manta_transfer(
				Origin::signed(1),
				root,
				sender_data,
				receiver_data,
				proof_bytes,
			));

			// check the resulting status of the ledger storage
			assert_eq!(TotalSupply::get(), 100000);
			assert_eq!(PoolBalance::get(), pool);
			let coin_list = CoinList::get();
			assert_eq!(coin_list.len(), size + 1 + i);
			assert_eq!(coin_list[i], senders[i].0.cm_bytes);
			assert_eq!(coin_list[size + i], receivers[i].0.cm_bytes);
			let sn_list = SNList::get();
			assert_eq!(sn_list.len(), i + 1);
			assert_eq!(sn_list[i], senders[i].2.sn);
			let enc_value_list = EncValueList::get();
			assert_eq!(enc_value_list.len(), i + 1);
			assert_eq!(enc_value_list[i], cipher);
			assert_eq!(
				manta_dh_dec(&cipher, &sender_pk_bytes, &receiver_sk_bytes),
				10 + i as u64
			);
		}
	});
}

// #[ignore]
#[test]
fn test_reclaim_should_work() {
	new_test_ext().execute_with(|| {
		// setup
		assert_ok!(Assets::init(Origin::signed(1), 100000));
		assert_eq!(Assets::balance(1), 100000);
		assert_eq!(PoolBalance::get(), 0);

		let hash_param = HashParam::deserialize(HASHPARAMBYTES.as_ref());
		let commit_param = MantaCoinCommitmentParam::deserialize(COMPARAMBYTES.as_ref());

		let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
		let mut pool = 0;
		let size = 10usize;

		// sender tokens
		let mut senders = Vec::new();
		for i in 0usize..size {
			// build a sender token
			let mut sk = [0u8; 32];
			let token_value = 10 + i as u64;
			rng.fill_bytes(&mut sk);
			let (sender, sender_pub_info, sender_priv_info) =
				make_coin(&commit_param, sk, token_value, &mut rng);
			senders.push((sender, sender_pub_info, sender_priv_info));

			let mut mint_data = [0u8; 96];
			mint_data.copy_from_slice(
				[
					senders[i].0.cm_bytes.clone(),
					senders[i].1.k,
					senders[i].1.s,
				]
				.concat()
				.as_ref(),
			);

			// mint a sender token
			assert_ok!(Assets::mint(Origin::signed(1), token_value, mint_data));

			pool += token_value;

			// sanity checks
			assert_eq!(PoolBalance::get(), pool);
			let coin_list = CoinList::get();
			assert_eq!(coin_list.len(), i + 1);
			assert_eq!(coin_list[i], senders[i].0.cm_bytes);
			let sn_list = SNList::get();
			assert_eq!(sn_list.len(), 0);
		}

		// build ZKP circuit
		let mut file = File::open("reclaim_pk.bin").unwrap();
		let mut reclaim_pk_bytes: Vec<u8> = vec![];
		file.read_to_end(&mut reclaim_pk_bytes).unwrap();
		let pk = Groth16PK::deserialize_uncompressed(reclaim_pk_bytes.as_ref()).unwrap();

		// generate and verify transactions
		let coin_list = CoinList::get();
		let root = LedgerState::get();

		for i in 0usize..size {
			let token_value = 10 + i as u64;
			// generate ZKP
			let circuit = ReclaimCircuit {
				commit_param: commit_param.clone(),
				hash_param: hash_param.clone(),
				sender_coin: senders[i].0.clone(),
				sender_pub_info: senders[i].1.clone(),
				sender_priv_info: senders[i].2.clone(),
				value: token_value,
				list: coin_list.to_vec(),
			};

			let sanity_cs = ConstraintSystem::<Fq>::new_ref();
			circuit
				.clone()
				.generate_constraints(sanity_cs.clone())
				.unwrap();
			assert!(sanity_cs.is_satisfied().unwrap());

			let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();
			let vk_bytes = ReclaimZKPKey::get();
			let vk = Groth16VK::deserialize(vk_bytes.as_ref()).unwrap();
			assert_eq!(pk.vk, vk);

			let mut proof_bytes = [0u8; 192];
			proof.serialize(proof_bytes.as_mut()).unwrap();

			let mut sender_data = [0u8; 64];
			sender_data.copy_from_slice([senders[i].1.k, senders[i].2.sn].concat().as_ref());

			// make the reclaim
			assert_ok!(Assets::reclaim(
				Origin::signed(1),
				token_value,
				root,
				sender_data,
				proof_bytes,
			));

			// check the resulting status of the ledger storage
			assert_eq!(TotalSupply::get(), 100000);
			pool -= token_value;
			assert_eq!(PoolBalance::get(), pool);

			let sn_list = SNList::get();
			assert_eq!(sn_list.len(), i + 1);
			assert_eq!(sn_list[i], senders[i].2.sn);
		}
		let coin_list = CoinList::get();
		assert_eq!(coin_list.len(), size);
		let enc_value_list = EncValueList::get();
		assert_eq!(enc_value_list.len(), 0);
	});
}

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
