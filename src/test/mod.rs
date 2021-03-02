use super::*;
use crate::dh::*;
use crate::forfeit::*;
use crate::manta_token::*;
use crate::param::*;
use crate::serdes::*;
use crate::transfer::*;
use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{CommitmentScheme, FixedLengthCRH};
use ark_ed_on_bls12_381::Fq;
use ark_ff::ToConstraintField;
use ark_groth16::{create_random_proof, generate_random_parameters, verify_proof};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use data_encoding::BASE64;
use frame_support::{assert_noop, assert_ok, impl_outer_origin, parameter_types, weights::Weight};
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sp_core::H256;
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup},
    Perbill,
};
use std::fs::File;
use std::io::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};

impl_outer_origin! {
    pub enum Origin for Test where system = frame_system {}
}

#[derive(Clone, Eq, PartialEq)]
pub struct Test;
parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const MaximumBlockWeight: Weight = 1024;
    pub const MaximumBlockLength: u32 = 2 * 1024;
    pub const AvailableBlockRatio: Perbill = Perbill::one();
}
impl frame_system::Trait for Test {
    type BaseCallFilter = ();
    type Origin = Origin;
    type Index = u64;
    type Call = ();
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = ();
    type BlockHashCount = BlockHashCount;
    type MaximumBlockWeight = MaximumBlockWeight;
    type DbWeight = ();
    type BlockExecutionWeight = ();
    type ExtrinsicBaseWeight = ();
    type MaximumExtrinsicWeight = MaximumBlockWeight;
    type AvailableBlockRatio = AvailableBlockRatio;
    type MaximumBlockLength = MaximumBlockLength;
    type Version = ();
    type PalletInfo = ();
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
}
impl Trait for Test {
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
        let hash_param = hash_param_deserialize(HASHPARAMBYTES.as_ref());
        let commit_param = commit_param_deserialize(COMPARAMBYTES.as_ref());
        let hash_param_checksum_local = hash_param_checksum(&hash_param);
        let commit_param_checksum_local = commit_param_checksum(&commit_param);
        let hash_param_checksum = HashParamChecksum::get();
        let commit_param_checksum = CommitParamChecksum::get();
        assert_eq!(hash_param_checksum, hash_param_checksum_local);
        assert_eq!(commit_param_checksum, commit_param_checksum_local);
    });
}

#[test]
fn test_mint_hardcode_should_work() {
    new_test_ext().execute_with(|| {
        assert_ok!(Assets::init(Origin::signed(1), 1000));
        assert_eq!(Assets::balance(1), 1000);
        assert_eq!(PoolBalance::get(), 0);

        // those are parameters for coin_1 in coin.json
        let mut k_bytes = [0u8; 32];
        let k_vec = BASE64
            .decode(b"+tMTpSikpdACxuDGZTl5pxwT7tpYcX/DFKJRZ1oLfqc=")
            .unwrap();
        k_bytes.copy_from_slice(k_vec[0..32].as_ref());

        let mut s_bytes = [0u8; 32];
        let s_vec = BASE64
            .decode(b"xsPXqMXA1SKMOehtsgVWV8xw9Mj0rh3O8Yt1ZHJzaQ4=")
            .unwrap();
        s_bytes.copy_from_slice(s_vec[0..32].as_ref());

        let mut cm_bytes = [0u8; 32];
        let cm_vec = BASE64
            .decode(b"XzoWOzhp6rXjQ/HDEN6jSLsLs64hKXWUNuFVtCUq0AA=")
            .unwrap();
        cm_bytes.copy_from_slice(cm_vec[0..32].as_ref());

        let coin = MantaCoin {
            cm_bytes: cm_bytes.clone(),
        };

        assert_ok!(Assets::mint(
            Origin::signed(1),
            10,
            k_bytes,
            s_bytes,
            cm_bytes
        ));

        assert_eq!(TotalSupply::get(), 1000);
        assert_eq!(PoolBalance::get(), 10);
        let coin_list = CoinList::get();
        assert_eq!(coin_list.len(), 1);
        assert_eq!(coin_list[0], coin);

        // those are parameters for coin_2 in coin.json
        let mut k_bytes = [0u8; 32];
        let k_vec = BASE64
            .decode(b"CutG9BBbkJMpBkbYTVX37HWunGcxHyy8+Eb1xRT9eVM=")
            .unwrap();
        k_bytes.copy_from_slice(k_vec[0..32].as_ref());

        let mut s_bytes = [0u8; 32];
        let s_vec = BASE64
            .decode(b"/KTVGbHHU8UVHLS6h54470DtjwF6MHvBkG2bKxpyBQc=")
            .unwrap();
        s_bytes.copy_from_slice(s_vec[0..32].as_ref());

        let mut cm_bytes = [0u8; 32];
        let cm_vec = BASE64
            .decode(b"3Oye4AqhzdysdWdCzMcoImTnYNGd21OmF8ztph4dRqI=")
            .unwrap();
        cm_bytes.copy_from_slice(cm_vec[0..32].as_ref());

        let coin = MantaCoin {
            cm_bytes: cm_bytes.clone(),
        };

        assert_ok!(Assets::mint(
            Origin::signed(1),
            100,
            k_bytes,
            s_bytes,
            cm_bytes
        ));

        assert_eq!(TotalSupply::get(), 1000);
        assert_eq!(PoolBalance::get(), 110);
        let coin_list = CoinList::get();
        assert_eq!(coin_list.len(), 2);
        assert_eq!(coin_list[1], coin);

        let sn_list = SNList::get();
        assert_eq!(sn_list.len(), 0);
    });
}

#[test]
fn test_mint_should_work() {
    new_test_ext().execute_with(|| {
        assert_ok!(Assets::init(Origin::signed(1), 1000));
        assert_eq!(Assets::balance(1), 1000);
        assert_eq!(PoolBalance::get(), 0);
        let commit_param = commit_param_deserialize(COMPARAMBYTES.as_ref());
        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        let (coin, pub_info, _priv_info) = make_coin(&commit_param, sk, 10, &mut rng);
        assert_ok!(Assets::mint(
            Origin::signed(1),
            10,
            pub_info.k,
            pub_info.s,
            coin.cm_bytes
        ));

        assert_eq!(TotalSupply::get(), 1000);
        assert_eq!(PoolBalance::get(), 10);
        let coin_list = CoinList::get();
        assert_eq!(coin_list.len(), 1);
        assert_eq!(coin_list[0], coin);
        let sn_list = SNList::get();
        assert_eq!(sn_list.len(), 0);
    });
}

#[test]
fn test_transfer_hardcode_should_work() {
    new_test_ext().execute_with(|| {
        assert_ok!(Assets::init(Origin::signed(1), 1000));
        assert_eq!(Assets::balance(1), 1000);
        assert_eq!(PoolBalance::get(), 0);

        // hardcoded sender
        // those are parameters for coin_1 in coin.json
        let  mut old_k_bytes = [0u8;32];
        let old_k_vec = BASE64
            .decode(b"+tMTpSikpdACxuDGZTl5pxwT7tpYcX/DFKJRZ1oLfqc=")
            .unwrap();
        old_k_bytes.copy_from_slice(&old_k_vec[0..32].as_ref());

        let mut old_s_bytes = [0u8; 32];
        let old_s_vec = BASE64
            .decode(b"xsPXqMXA1SKMOehtsgVWV8xw9Mj0rh3O8Yt1ZHJzaQ4=")
            .unwrap();
        old_s_bytes.copy_from_slice(old_s_vec[0..32].as_ref());

        let mut old_cm_bytes = [0u8; 32];
        let old_cm_vec = BASE64
            .decode(b"XzoWOzhp6rXjQ/HDEN6jSLsLs64hKXWUNuFVtCUq0AA=")
            .unwrap();
        old_cm_bytes.copy_from_slice(&old_cm_vec[0..32].as_ref());

        let mut old_sn_bytes = [0u8; 32];
        let old_sn_vec = BASE64
            .decode(b"jqhzAPanABquT0CpMC2aFt2ze8+UqMUcUG6PZBmqFqE=")
            .unwrap();
        old_sn_bytes.copy_from_slice(&old_sn_vec[0..32].as_ref());

        let sender = MantaCoin {
            cm_bytes: old_cm_bytes.clone(),
        };

        // mint the sender coin
        assert_ok!(Assets::mint(
            Origin::signed(1),
            10,
            old_k_bytes,
            old_s_bytes,
            old_cm_bytes
        ));

        // check that minting is successful
        assert_eq!(PoolBalance::get(), 10);
        let coin_list = CoinList::get();
        assert_eq!(coin_list.len(), 1);
        assert_eq!(coin_list[0], sender);
        let sn_list = SNList::get();
        assert_eq!(sn_list.len(), 0);

        // hardcoded receiver
        // those are parameters for coin_3 in coin.json
        let  mut new_k_bytes = [0u8;32];
        let new_k_vec = BASE64
            .decode(b"2HbWGQCLOfxuA4jOiDftBRSbjjAs/a0vjrq/H4p6QBI=")
            .unwrap();
        new_k_bytes.copy_from_slice(&new_k_vec[0..32].as_ref());

        let mut new_cm_bytes = [0u8; 32];
        let new_cm_vec = BASE64
            .decode(b"1zuOv92V7e1qX1bP7+QNsV+gW5E3xUsghte/lZ7h5pg=")
            .unwrap();
        new_cm_bytes.copy_from_slice(new_cm_vec[0..32].as_ref());
        let receiver = MantaCoin{
            cm_bytes: new_cm_bytes,
        };

        // hardcoded proof
        let mut proof_bytes = [0u8; 192];
        let proof_vec = BASE64
            .decode(b"zU+xNmmLjmJAFy/sbxGR5fwik4nSddSjrn0YdygYlLSTvXHk8jVsjS4Sp4/0cuCHl+h9i9Scj5ok8q8R55QL2xuBZS7L0++N8BVL1HqzO0yFhrKiuScIg0cKWZYg76oBSK0xAbsMvmEoh+DQCsWG5Hfcey8BSXiaEck1LJFzpvRSqqsKChLC8cDN3fLH8fMJHh5tnAXDmMoOrKH2r7v7c0IJh0JjlWgazCEt9xb/89467vUfNAJ8jzIRl9zqsuqH")
            .unwrap();
        proof_bytes.copy_from_slice(proof_vec[0..192].as_ref());

        // hardcoded keys and ciphertext
        let mut cipher_bytes = [0u8; 16];
        let cipher_vec =  BASE64
            .decode(b"UkNssYxe5HUjSzlz5JE1pQ==")
            .unwrap();
        cipher_bytes.copy_from_slice(cipher_vec[0..16].as_ref());

        let mut sender_pk_bytes = [0u8; 32];
        let sender_pk_vec =  BASE64
            .decode(b"YNwLbvb27Rb0aKptzSNEvBToYvW9IlbjVvROHfD2NAQ=")
            .unwrap();
        sender_pk_bytes.copy_from_slice(sender_pk_vec[0..32].as_ref());

        let mut receiver_sk_bytes = [0u8; 32];
        let receiver_sk_vec =  BASE64
            .decode(b"uPo5YiD6wGRiHbIXH6WmHuwjYS+mNSkCspDngkHHJ2c=")
            .unwrap();
        receiver_sk_bytes.copy_from_slice(receiver_sk_vec[0..32].as_ref());


        // hardcoded merkle root
        let mut root_bytes = [0u8; 32];
        let root_vec = BASE64
            .decode(b"q5VhDl/WxjeemZ/2ivGmiuOTFMEazcqEFk5ESISngso=")
            .unwrap();
        root_bytes.copy_from_slice(root_vec[0..32].as_ref());

        // make the transfer
        assert_ok!(Assets::manta_transfer(
            Origin::signed(1),
            root_bytes,
            old_sn_bytes,
            old_k_bytes,
            new_k_bytes,
            new_cm_bytes,
            cipher_bytes,
            proof_bytes,
        ));

        // check the resulting status of the ledger storage
        assert_eq!(TotalSupply::get(), 1000);
        assert_eq!(PoolBalance::get(), 10);
        let coin_list = CoinList::get();
        assert_eq!(coin_list.len(), 2);
        assert_eq!(coin_list[0], sender);
        assert_eq!(coin_list[1], receiver);
        let sn_list = SNList::get();
        assert_eq!(sn_list.len(), 1);
        assert_eq!(sn_list[0], old_sn_bytes);

        let enc_value_list = EncValueList::get();
        assert_eq!(enc_value_list.len(), 1);
        assert_eq!(enc_value_list[0], cipher_bytes);
        assert_eq!(
            dh::manta_dh_dec(&cipher_bytes, &sender_pk_bytes, &receiver_sk_bytes),
            10
        );

        // todo: check the ledger state is correctly updated
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

        let hash_param = hash_param_deserialize(HASHPARAMBYTES.as_ref());
        let commit_param = commit_param_deserialize(COMPARAMBYTES.as_ref());

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

            // mint a sender token
            assert_ok!(Assets::mint(
                Origin::signed(1),
                token_value,
                senders[i].1.k,
                senders[i].1.s,
                senders[i].0.cm_bytes
            ));

            pool += token_value;

            // sanity checks
            assert_eq!(PoolBalance::get(), pool);
            let coin_list = CoinList::get();
            assert_eq!(coin_list.len(), i + 1);
            assert_eq!(coin_list[i], senders[i].0);
            let sn_list = SNList::get();
            assert_eq!(sn_list.len(), 0);
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
            let list = coin_list.iter().map(|x| x.cm_bytes).collect();
            // generate ZKP
            let circuit = TransferCircuit {
                commit_param: commit_param.clone(),
                hash_param: hash_param.clone(),
                sender_coin: senders[i].0.clone(),
                sender_pub_info: senders[i].1.clone(),
                sender_priv_info: senders[i].2.clone(),
                receiver_coin: receivers[i].0.clone(),
                receiver_pub_info: receivers[i].1.clone(),
                list,
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

            assert_ok!(Assets::manta_transfer(
                Origin::signed(1),
                root,
                senders[i].2.sn,
                senders[i].1.k,
                receivers[i].1.k,
                receivers[i].0.cm_bytes,
                cipher,
                proof_bytes,
            ));

            // check the resulting status of the ledger storage
            assert_eq!(TotalSupply::get(), 100000);
            assert_eq!(PoolBalance::get(), pool);
            let coin_list = CoinList::get();
            assert_eq!(coin_list.len(), size + 1 + i);
            assert_eq!(coin_list[i], senders[i].0);
            assert_eq!(coin_list[size + i], receivers[i].0);
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

#[test]
fn test_forfeit_hardcode_should_work() {
    new_test_ext().execute_with(|| {
        assert_ok!(Assets::init(Origin::signed(1), 1000));
        assert_eq!(Assets::balance(1), 1000);
        assert_eq!(PoolBalance::get(), 0);


        // hardcoded coin_1
        // those are parameters for coin_1 in coin.json
        let  mut old_k_bytes = [0u8;32];
        let old_k_vec = BASE64
            .decode(b"+tMTpSikpdACxuDGZTl5pxwT7tpYcX/DFKJRZ1oLfqc=")
            .unwrap();
        old_k_bytes.copy_from_slice(&old_k_vec[0..32].as_ref());

        let mut old_s_bytes = [0u8; 32];
        let old_s_vec = BASE64
            .decode(b"xsPXqMXA1SKMOehtsgVWV8xw9Mj0rh3O8Yt1ZHJzaQ4=")
            .unwrap();
        old_s_bytes.copy_from_slice(old_s_vec[0..32].as_ref());

        let mut old_cm_bytes = [0u8; 32];
        let old_cm_vec = BASE64
            .decode(b"XzoWOzhp6rXjQ/HDEN6jSLsLs64hKXWUNuFVtCUq0AA=")
            .unwrap();
        old_cm_bytes.copy_from_slice(&old_cm_vec[0..32].as_ref());

        let mut old_sn_bytes = [0u8; 32];
        let old_sn_vec = BASE64
            .decode(b"jqhzAPanABquT0CpMC2aFt2ze8+UqMUcUG6PZBmqFqE=")
            .unwrap();
        old_sn_bytes.copy_from_slice(&old_sn_vec[0..32].as_ref());

        let sender = MantaCoin {
            cm_bytes: old_cm_bytes.clone(),
        };

        // mint the sender coin
        assert_ok!(Assets::mint(
            Origin::signed(1),
            10,
            old_k_bytes,
            old_s_bytes,
            old_cm_bytes
        ));

        // check that minting is successful
        assert_eq!(PoolBalance::get(), 10);
        let coin_list = CoinList::get();
        assert_eq!(coin_list.len(), 1);
        assert_eq!(coin_list[0], sender);
        let sn_list = SNList::get();
        assert_eq!(sn_list.len(), 0);


        // hardcoded sender
        // those are parameters for coin_1 in coin.json
        let  mut old_k_bytes = [0u8;32];
        let old_k_vec = BASE64
            .decode(b"CutG9BBbkJMpBkbYTVX37HWunGcxHyy8+Eb1xRT9eVM=")
            .unwrap();
        old_k_bytes.copy_from_slice(&old_k_vec[0..32].as_ref());

        let mut old_s_bytes = [0u8; 32];
        let old_s_vec = BASE64
            .decode(b"/KTVGbHHU8UVHLS6h54470DtjwF6MHvBkG2bKxpyBQc=")
            .unwrap();
        old_s_bytes.copy_from_slice(old_s_vec[0..32].as_ref());

        let mut old_cm_bytes = [0u8; 32];
        let old_cm_vec = BASE64
            .decode(b"3Oye4AqhzdysdWdCzMcoImTnYNGd21OmF8ztph4dRqI=")
            .unwrap();
        old_cm_bytes.copy_from_slice(&old_cm_vec[0..32].as_ref());

        let mut old_sn_bytes = [0u8; 32];
        let old_sn_vec = BASE64
            .decode(b"EdHWc+HAgRWlcJrK8dlVnewSCTwEDPZFa8iYKxoRdOY=")
            .unwrap();
        old_sn_bytes.copy_from_slice(&old_sn_vec[0..32].as_ref());

        let sender = MantaCoin {
            cm_bytes: old_cm_bytes.clone(),
        };

        // mint the sender coin
        assert_ok!(Assets::mint(
            Origin::signed(1),
            100,
            old_k_bytes,
            old_s_bytes,
            old_cm_bytes
        ));

        // check that minting is successful
        assert_eq!(PoolBalance::get(), 110);
        let coin_list = CoinList::get();
        assert_eq!(coin_list.len(), 2);
        assert_eq!(coin_list[1], sender);
        let sn_list = SNList::get();
        assert_eq!(sn_list.len(), 0);


        // hardcoded proof
        let mut proof_bytes = [0u8; 192];
        let proof_vec = BASE64
            .decode(b"yT4284c8SiAC1i85GIgmOJa20KjLGWGTrdsvLOo6bbPgtPO8qDpK8y6OtiOa1qqSxm+tp1CAjxdyrTQ6QkZqUQfJs51cvrp9vYYscY2LqqRcuYL1T7LRq/IcofgJZf8YyRH3HWnz5Vj/bXmFAVlLgs/fbWYgzoFHbOlZpva+RMgCMuJ/2ltRAfpKDI7meMgBwEMSz93OPGv+txf0yhVqydpSVrFdB/zwd09mWW/7OuCYRzXcvmBuL3HGzbsGiLkG")
            .unwrap();
        proof_bytes.copy_from_slice(proof_vec[0..192].as_ref());

        // hardcoded merkle root
        let mut root_bytes = [0u8; 32];
        let root_vec = BASE64
            .decode(b"QDWIJvSmMmIS1incXpqZA+oZKOuvP42PNVyLKWC0gGQ=")
            .unwrap();
        root_bytes.copy_from_slice(root_vec[0..32].as_ref());

        // make the transfer
        assert_ok!(Assets::forfeit(
            Origin::signed(1),
            100,
            root_bytes,
            old_sn_bytes,
            old_k_bytes,
            proof_bytes,
        ));

        // check the resulting status of the ledger storage
        assert_eq!(TotalSupply::get(), 1000);
        assert_eq!(PoolBalance::get(), 10);
        let coin_list = CoinList::get();
        assert_eq!(coin_list.len(), 2);
        let sn_list = SNList::get();
        assert_eq!(sn_list.len(), 1);
        assert_eq!(sn_list[0], old_sn_bytes);

    });
}

/// this is a local test on zero knowledge proof generation and verifications
#[test]
fn test_forfeit_zkp_local() {
    let hash_param = hash_param_deserialize(HASHPARAMBYTES.as_ref());
    let commit_param = commit_param_deserialize(COMPARAMBYTES.as_ref());

    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);

    // sender
    let value = 100;
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);
    let (sender, sender_pub_info, sender_priv_info) = make_coin(&commit_param, sk, value, &mut rng);

    // list of commitment
    let mut list = vec![sender.cm_bytes.clone()];
    for _e in 1..24 {
        let mut cm_rand = [0u8; 32];
        rng.fill_bytes(&mut cm_rand);
        list.push(cm_rand);
    }
    let tree = LedgerMerkleTree::new(hash_param.clone(), &list).unwrap();
    let merkle_root = tree.root();

    let circuit = ForfeitCircuit {
        commit_param: commit_param.clone(),
        hash_param: hash_param.clone(),
        sender_coin: sender.clone(),
        sender_pub_info: sender_pub_info.clone(),
        sender_priv_info: sender_priv_info.clone(),
        value,
        list: list.clone(),
    };

    let sanity_cs = ConstraintSystem::<Fq>::new_ref();
    circuit
        .clone()
        .generate_constraints(sanity_cs.clone())
        .unwrap();
    assert!(sanity_cs.is_satisfied().unwrap());

    let pk = generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng).unwrap();
    let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();
    let pvk = Groth16PVK::from(pk.vk.clone());

    let k_old = MantaCoinCommitmentOutput::deserialize(sender_pub_info.k.as_ref()).unwrap();

    // format the input to the verification
    let mut inputs = [k_old.x, k_old.y].to_vec();
    let sn: Vec<Fq> =
        ToConstraintField::<Fq>::to_field_elements(sender_priv_info.sn.as_ref()).unwrap();
    let mr: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&merkle_root).unwrap();
    let value_fq = Fq::from(value);
    inputs = [
        inputs[..].as_ref(),
        sn.as_ref(),
        mr.as_ref(),
        [value_fq].as_ref(),
    ]
    .concat();

    assert!(verify_proof(&pvk, &proof, &inputs[..]).unwrap());
}

// #[ignore]
#[test]
fn test_forfeit_should_work() {
    new_test_ext().execute_with(|| {
        // setup
        assert_ok!(Assets::init(Origin::signed(1), 100000));
        assert_eq!(Assets::balance(1), 100000);
        assert_eq!(PoolBalance::get(), 0);

        let hash_param = hash_param_deserialize(HASHPARAMBYTES.as_ref());
        let commit_param = commit_param_deserialize(COMPARAMBYTES.as_ref());

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

            // mint a sender token
            assert_ok!(Assets::mint(
                Origin::signed(1),
                token_value,
                senders[i].1.k,
                senders[i].1.s,
                senders[i].0.cm_bytes
            ));

            pool += token_value;

            // sanity checks
            assert_eq!(PoolBalance::get(), pool);
            let coin_list = CoinList::get();
            assert_eq!(coin_list.len(), i + 1);
            assert_eq!(coin_list[i], senders[i].0);
            let sn_list = SNList::get();
            assert_eq!(sn_list.len(), 0);
        }

        // build ZKP circuit
        let mut file = File::open("forfeit_pk.bin").unwrap();
        let mut forfeit_pk_bytes: Vec<u8> = vec![];
        file.read_to_end(&mut forfeit_pk_bytes).unwrap();
        let pk = Groth16PK::deserialize_uncompressed(forfeit_pk_bytes.as_ref()).unwrap();

        // generate and verify transactions
        let coin_list = CoinList::get();
        let root = LedgerState::get();
        let list: Vec<[u8; 32]> = coin_list.iter().map(|x| x.cm_bytes).collect();

        for i in 0usize..size {
            let token_value = 10 + i as u64;
            // generate ZKP
            let circuit = ForfeitCircuit {
                commit_param: commit_param.clone(),
                hash_param: hash_param.clone(),
                sender_coin: senders[i].0.clone(),
                sender_pub_info: senders[i].1.clone(),
                sender_priv_info: senders[i].2.clone(),
                value: token_value,
                list: list.clone(),
            };

            let sanity_cs = ConstraintSystem::<Fq>::new_ref();
            circuit
                .clone()
                .generate_constraints(sanity_cs.clone())
                .unwrap();
            assert!(sanity_cs.is_satisfied().unwrap());

            let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();
            let vk_bytes = ForfeitZKPKey::get();
            let vk = Groth16VK::deserialize(vk_bytes.as_ref()).unwrap();
            assert_eq!(pk.vk, vk);

            let mut proof_bytes = [0u8; 192];
            proof.serialize(proof_bytes.as_mut()).unwrap();

            // make the forfeit
            assert_ok!(Assets::forfeit(
                Origin::signed(1),
                token_value,
                root,
                senders[i].2.sn,
                senders[i].1.k,
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

/// this is a local test on zero knowledge proof generation and verifications
#[test]
fn test_transfer_zkp_local() {
    let hash_param = hash_param_deserialize(HASHPARAMBYTES.as_ref());
    let commit_param = commit_param_deserialize(COMPARAMBYTES.as_ref());

    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);

    // sender
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);
    let (sender, sender_pub_info, sender_priv_info) = make_coin(&commit_param, sk, 100, &mut rng);

    // receiver
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);
    let (receiver, receiver_pub_info, _receiver_priv_info) =
        make_coin(&commit_param, sk, 100, &mut rng);

    // list of commitment
    let mut list = vec![sender.cm_bytes.clone()];
    for _e in 1..24 {
        let mut cm_rand = [0u8; 32];
        rng.fill_bytes(&mut cm_rand);
        list.push(cm_rand);
    }
    let tree = LedgerMerkleTree::new(hash_param.clone(), &list).unwrap();
    let merkle_root = tree.root();

    let circuit = TransferCircuit {
        commit_param: commit_param.clone(),
        hash_param: hash_param.clone(),
        sender_coin: sender.clone(),
        sender_pub_info: sender_pub_info.clone(),
        sender_priv_info: sender_priv_info.clone(),
        receiver_coin: receiver.clone(),
        receiver_pub_info: receiver_pub_info.clone(),
        list: list.clone(),
    };

    let sanity_cs = ConstraintSystem::<Fq>::new_ref();
    circuit
        .clone()
        .generate_constraints(sanity_cs.clone())
        .unwrap();
    assert!(sanity_cs.is_satisfied().unwrap());

    let pk = generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng).unwrap();
    let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();
    let pvk = Groth16PVK::from(pk.vk.clone());

    let k_old = MantaCoinCommitmentOutput::deserialize(sender_pub_info.k.as_ref()).unwrap();
    let k_new = MantaCoinCommitmentOutput::deserialize(receiver_pub_info.k.as_ref()).unwrap();
    let cm_new = MantaCoinCommitmentOutput::deserialize(receiver.cm_bytes.as_ref()).unwrap();

    // format the input to the verification
    let mut inputs = [k_old.x, k_old.y, k_new.x, k_new.y, cm_new.x, cm_new.y].to_vec();
    let sn: Vec<Fq> =
        ToConstraintField::<Fq>::to_field_elements(sender_priv_info.sn.as_ref()).unwrap();
    let mr: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&merkle_root).unwrap();
    inputs = [inputs[..].as_ref(), sn.as_ref(), mr.as_ref()].concat();

    assert!(verify_proof(&pvk, &proof, &inputs[..]).unwrap());

    // with a new sender at another position of the leaf
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);
    let (sender2, sender_pub_info2, sender_priv_info2) =
        make_coin(&commit_param, sk, 100, &mut rng);
    list.push(sender2.cm_bytes);
    let tree = LedgerMerkleTree::new(hash_param.clone(), &list).unwrap();
    let merkle_root = tree.root();

    let circuit = TransferCircuit {
        commit_param: commit_param.clone(),
        hash_param,
        sender_coin: sender2.clone(),
        sender_pub_info: sender_pub_info2.clone(),
        sender_priv_info: sender_priv_info2.clone(),
        receiver_coin: receiver.clone(),
        receiver_pub_info: receiver_pub_info.clone(),
        list,
    };

    let sanity_cs = ConstraintSystem::<Fq>::new_ref();
    circuit
        .clone()
        .generate_constraints(sanity_cs.clone())
        .unwrap();
    assert!(sanity_cs.is_satisfied().unwrap());

    let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();
    let k_old = MantaCoinCommitmentOutput::deserialize(sender_pub_info2.k.as_ref()).unwrap();
    let mut inputs = [k_old.x, k_old.y, k_new.x, k_new.y, cm_new.x, cm_new.y].to_vec();
    let sn: Vec<Fq> =
        ToConstraintField::<Fq>::to_field_elements(sender_priv_info2.sn.as_ref()).unwrap();
    let mr: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&merkle_root).unwrap();
    inputs = [inputs[..].as_ref(), sn.as_ref(), mr.as_ref()].concat();
    assert!(verify_proof(&pvk, &proof, &inputs[..]).unwrap());
}

#[test]
fn manta_dh() {
    let mut rng = rand::thread_rng();
    let receiver_sk = StaticSecret::new(rng);
    let receiver_pk = PublicKey::from(&receiver_sk);
    let receiver_pk_bytes = receiver_pk.to_bytes();
    let receiver_sk_bytes = receiver_sk.to_bytes();
    let value = 12345678;
    let (sender_pk_bytes, cipher) = manta_dh_enc(&receiver_pk_bytes, value, &mut rng);
    println!("enc success");
    let rec_value = manta_dh_dec(&cipher, &sender_pk_bytes, &receiver_sk_bytes);
    assert_eq!(value, rec_value);
}

#[test]
fn test_param_serdes() {
    let hash_param_seed = [1u8; 32];
    let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
    let hash_param = Hash::setup(&mut rng).unwrap();
    let mut buf: Vec<u8> = vec![];

    hash_param_serialize(&hash_param, &mut buf);
    let hash_param2: HashParam = hash_param_deserialize(buf.as_ref());
    assert_eq!(hash_param.generators, hash_param2.generators);

    let commit_param_seed = [2u8; 32];
    let mut rng = ChaCha20Rng::from_seed(commit_param_seed);
    let commit_param = MantaCoinCommitmentScheme::setup(&mut rng).unwrap();
    let mut buf: Vec<u8> = vec![];

    commit_param_serialize(&commit_param, &mut buf);
    let commit_param2 = commit_param_deserialize(buf.as_ref());
    assert_eq!(commit_param.generators, commit_param2.generators);
    assert_eq!(
        commit_param.randomness_generator,
        commit_param2.randomness_generator
    );
}
