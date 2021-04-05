use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{CommitmentScheme as ArkCommitmentScheme, FixedLengthCRH};
use ark_ed_on_bls12_381::Fq;
use ark_groth16::generate_random_parameters;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use hkdf::Hkdf;
use pallet_manta_pay::*;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::Sha512Trunc256;
use std::{fs::File, io::prelude::*};

fn main() {
	println!("Hello, Manta!");
	write_zkp_keys();
}

fn write_zkp_keys() {
	let hash_param_seed = [1u8; 32];
	let commit_param_seed = [2u8; 32];
	let seed = [3u8; 32];
	let rng_salt: [u8; 32] = [
		0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x73, 0x65, 0x65, 0x64, 0x20,
		0x66, 0x6f, 0x72, 0x20, 0x6d, 0x61, 0x6e, 0x74, 0x61, 0x20, 0x7a, 0x6b, 0x20, 0x74, 0x65,
		0x73, 0x74,
	];
	let mut rng_seed = [0u8; 32];
	let digest = Hkdf::<Sha512Trunc256>::extract(Some(rng_salt.as_ref()), &seed);
	rng_seed.copy_from_slice(&digest.0[0..32]);

	let mut transfer_pk_bytes =
		manta_transfer_zkp_key_gen(&hash_param_seed, &commit_param_seed, &rng_seed);
	let mut file = File::create("transfer_pk.bin").unwrap();
	file.write_all(transfer_pk_bytes.as_mut()).unwrap();
	// println!("transfer circuit pk length: {}", transfer_pk_bytes.len());

	let mut reclaim_pk_bytes =
		manta_reclaim_zkp_key_gen(&hash_param_seed, &commit_param_seed, &rng_seed);
	let mut file = File::create("reclaim_pk.bin").unwrap();
	file.write_all(reclaim_pk_bytes.as_mut()).unwrap();
	// println!("reclaim circuit pk length: {}", reclaim_pk_bytes.len());
}

fn manta_transfer_zkp_key_gen(
	hash_param_seed: &[u8; 32],
	commit_param_seed: &[u8; 32],
	rng_seed: &[u8; 32],
) -> Vec<u8> {
	// rebuild the parameters from the inputs
	let mut rng = ChaCha20Rng::from_seed(*commit_param_seed);
	let commit_param = CommitmentScheme::setup(&mut rng).unwrap();

	let mut rng = ChaCha20Rng::from_seed(*hash_param_seed);
	let hash_param = Hash::setup(&mut rng).unwrap();

	let mut rng = ChaCha20Rng::from_seed(*rng_seed);
	let mut coins = Vec::new();
	let mut ledger = Vec::new();
	let mut sk = [0u8; 32];

	for e in 0..128 {
		rng.fill_bytes(&mut sk);

		let sender = make_coin(&commit_param, sk, e + 100, &mut rng);
		ledger.push(sender.0.cm_bytes);
		coins.push(sender);
	}

	// sender's total value is 210
	let sender_1 = coins[0].clone();
	let sender_2 = coins[10].clone();

	let tree = LedgerMerkleTree::new(hash_param.clone(), &ledger).unwrap();
	let index_1 = ledger
		.iter()
		.position(|x| *x == sender_1.0.cm_bytes)
		.unwrap();
	let path_1 = tree.generate_proof(index_1, &sender_1.0.cm_bytes).unwrap();
	let index_2 = ledger
		.iter()
		.position(|x| *x == sender_2.0.cm_bytes)
		.unwrap();
	let path_2 = tree.generate_proof(index_2, &sender_2.0.cm_bytes).unwrap();
	let root = tree.root();

	// receiver's total value is also 210
	rng.fill_bytes(&mut sk);
	let receiver_1 = make_coin(&commit_param, sk, 80, &mut rng);
	let receiver_2 = make_coin(&commit_param, sk, 130, &mut rng);

	// transfer circuit
	let transfer_circuit = TransferCircuit {
		// param
		commit_param,
		hash_param,

		// sender
		sender_coin_1: sender_1.0,
		sender_pub_info_1: sender_1.1,
		sender_priv_info_1: sender_1.2,
		sender_membership_1: path_1,
		root_1: root,

		sender_coin_2: sender_2.0,
		sender_pub_info_2: sender_2.1,
		sender_priv_info_2: sender_2.2,
		sender_membership_2: path_2,
		root_2: root,

		// receiver
		receiver_coin_1: receiver_1.0.clone(),
		receiver_k_1: receiver_1.1.k,
		receiver_s_1: receiver_1.1.s,
		receiver_value_1: receiver_1.2.value,

		receiver_coin_2: receiver_2.0.clone(),
		receiver_k_2: receiver_2.1.k,
		receiver_s_2: receiver_2.1.s,
		receiver_value_2: receiver_2.2.value,
	};

	let sanity_cs = ConstraintSystem::<Fq>::new_ref();
	transfer_circuit
		.clone()
		.generate_constraints(sanity_cs.clone())
		.unwrap();
	assert!(sanity_cs.is_satisfied().unwrap());

	// transfer pk_bytes
	let mut rng = ChaCha20Rng::from_seed(*rng_seed);
	let pk = generate_random_parameters::<Bls12_381, _, _>(transfer_circuit, &mut rng).unwrap();
	let mut transfer_pk_bytes: Vec<u8> = Vec::new();

	let mut vk_buf: Vec<u8> = vec![];
	let transfer_vk = &pk.vk;
	transfer_vk.serialize(&mut vk_buf).unwrap();
	println!("pk_uncompressed len {}", transfer_pk_bytes.len());
	println!("vk: {:?}", vk_buf);

	pk.serialize_uncompressed(&mut transfer_pk_bytes).unwrap();
	transfer_pk_bytes
}

fn manta_reclaim_zkp_key_gen(
	hash_param_seed: &[u8; 32],
	commit_param_seed: &[u8; 32],
	rng_seed: &[u8; 32],
) -> Vec<u8> {
	// rebuild the parameters from the inputs
	let mut rng = ChaCha20Rng::from_seed(*commit_param_seed);
	let commit_param = CommitmentScheme::setup(&mut rng).unwrap();

	let mut rng = ChaCha20Rng::from_seed(*hash_param_seed);
	let hash_param = Hash::setup(&mut rng).unwrap();

	let mut rng = ChaCha20Rng::from_seed(*rng_seed);
	let mut coins = Vec::new();
	let mut ledger = Vec::new();
	let mut sk = [0u8; 32];

	for e in 0..128 {
		rng.fill_bytes(&mut sk);

		let sender = make_coin(&commit_param, sk, e + 100, &mut rng);
		ledger.push(sender.0.cm_bytes);
		coins.push(sender);
	}
	// sender's total value is 210
	let sender_1 = coins[0].clone();
	let sender_2 = coins[10].clone();

	let tree = LedgerMerkleTree::new(hash_param.clone(), &ledger).unwrap();
	let index_1 = ledger
		.iter()
		.position(|x| *x == sender_1.0.cm_bytes)
		.unwrap();
	let path_1 = tree.generate_proof(index_1, &sender_1.0.cm_bytes).unwrap();
	let index_2 = ledger
		.iter()
		.position(|x| *x == sender_2.0.cm_bytes)
		.unwrap();
	let path_2 = tree.generate_proof(index_2, &sender_2.0.cm_bytes).unwrap();
	let root = tree.root();

	// receiver's total value is also 210
	rng.fill_bytes(&mut sk);
	let receiver = make_coin(&commit_param, sk, 80, &mut rng);

	// transfer circuit
	let reclaim_circuit = ReclaimCircuit {
		// param
		commit_param,
		hash_param,

		// sender
		sender_coin_1: sender_1.0,
		sender_pub_info_1: sender_1.1,
		sender_priv_info_1: sender_1.2,
		sender_membership_1: path_1,
		root_1: root,

		sender_coin_2: sender_2.0,
		sender_pub_info_2: sender_2.1,
		sender_priv_info_2: sender_2.2,
		sender_membership_2: path_2,
		root_2: root,

		// receiver
		receiver_coin: receiver.0,
		receiver_k: receiver.1.k,
		receiver_s: receiver.1.s,
		receiver_value: receiver.2.value,

		// reclaim value
		reclaim_value: 130,
	};

	let sanity_cs = ConstraintSystem::<Fq>::new_ref();
	reclaim_circuit
		.clone()
		.generate_constraints(sanity_cs.clone())
		.unwrap();
	assert!(sanity_cs.is_satisfied().unwrap());

	// reclaim pk_bytes
	let mut rng = ChaCha20Rng::from_seed(*rng_seed);
	let pk = generate_random_parameters::<Bls12_381, _, _>(reclaim_circuit, &mut rng).unwrap();
	let mut reclaim_pk_bytes: Vec<u8> = Vec::new();

	let mut vk_buf: Vec<u8> = vec![];
	let reclaim_vk = &pk.vk;
	reclaim_vk.serialize(&mut vk_buf).unwrap();
	println!("pk_uncompressed len {}", reclaim_pk_bytes.len());
	println!("vk: {:?}", vk_buf);

	pk.serialize_uncompressed(&mut reclaim_pk_bytes).unwrap();
	reclaim_pk_bytes
}
