#[macro_use]
extern crate criterion;
extern crate pallet_manta_pay;

use ark_crypto_primitives::{
	commitment::pedersen::Randomness, CommitmentScheme as ArkCommitmentScheme, FixedLengthCRH,
};
use ark_ed_on_bls12_381::{Fq, Fr};
use ark_groth16::create_random_proof;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use criterion::{Benchmark, Criterion};
use data_encoding::BASE64;
use pallet_manta_pay::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;
use std::{fs::File, io::prelude::*};

criterion_group!(
	manta_bench,
	bench_param_io,
	bench_pedersen_hash,
	bench_pedersen_com,
	bench_merkle_tree,
	bench_transfer_prove,
	bench_trasnfer_verify,
);
criterion_main!(manta_bench);

fn bench_param_io(c: &mut Criterion) {
	let bench_str = format!("hash param");
	let bench = Benchmark::new(bench_str, move |b| {
		b.iter(|| {
			HashParam::deserialize(HASH_PARAM_BYTES.as_ref());
		})
	});

	let bench_str = format!("commit param");
	let bench = bench.with_function(bench_str, move |b| {
		b.iter(|| {
			CommitmentParam::deserialize(COMMIT_PARAM_BYTES.as_ref());
		})
	});

	// let bench = bench.sample_size(10);
	c.bench("deserialization", bench);
}

fn bench_trasnfer_verify(c: &mut Criterion) {
	let hash_param_seed = HASH_PARAM_SEED;
	let commit_param_seed = COMMIT_PARAM_SEED;

	let mut rng = ChaCha20Rng::from_seed(commit_param_seed);
	let commit_param = CommitmentScheme::setup(&mut rng).unwrap();

	let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
	let hash_param = Hash::setup(&mut rng).unwrap();

	let mut file = File::open("transfer_pk.bin").unwrap();
	let mut transfer_key_bytes: Vec<u8> = vec![];
	file.read_to_end(&mut transfer_key_bytes).unwrap();

	let pk = Groth16PK::deserialize_unchecked(transfer_key_bytes.as_ref()).unwrap();

	println!("proving key loaded from disk");

	// sender
	let mut sk = [0u8; 32];
	rng.fill_bytes(&mut sk);
	let sender_1 = make_coin(&commit_param, sk, 100, &mut rng);
	rng.fill_bytes(&mut sk);
	let sender_2 = make_coin(&commit_param, sk, 300, &mut rng);

	// receiver
	rng.fill_bytes(&mut sk);
	let receiver_1 = make_coin(&commit_param, sk, 150, &mut rng);
	rng.fill_bytes(&mut sk);
	let receiver_2 = make_coin(&commit_param, sk, 250, &mut rng);

	// merkle tree
	let tree = LedgerMerkleTree::new(
		hash_param.clone(),
		&[sender_1.0.cm_bytes, sender_2.0.cm_bytes],
	)
	.unwrap();
	let root = tree.root();
	let path_1 = tree.generate_proof(0, &sender_1.0.cm_bytes).unwrap();
	let path_2 = tree.generate_proof(1, &sender_2.0.cm_bytes).unwrap();

	let circuit = TransferCircuit {
		commit_param: commit_param.clone(),
		hash_param,

		sender_coin_1: sender_1.0.clone(),
		sender_pub_info_1: sender_1.1.clone(),
		sender_priv_info_1: sender_1.2.clone(),
		sender_membership_1: path_1.clone(),
		root_1: root.clone(),

		sender_coin_2: sender_2.0.clone(),
		sender_pub_info_2: sender_2.1.clone(),
		sender_priv_info_2: sender_2.2.clone(),
		sender_membership_2: path_2.clone(),
		root_2: root,

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
	circuit
		.clone()
		.generate_constraints(sanity_cs.clone())
		.unwrap();
	assert!(sanity_cs.is_satisfied().unwrap());

	println!("creating the proof");
	let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();
	let mut proof_bytes = [0u8; 192];
	proof.serialize(proof_bytes.as_mut()).unwrap();

	let mut merkle_root_bytes = [0u8; 32];
	root.serialize(merkle_root_bytes.as_mut()).unwrap();
	let sender_data_1 = SenderData {
		k: sender_1.1.k,
		sn: sender_1.2.sn,
		root: merkle_root_bytes,
	};
	let sender_data_2 = SenderData {
		k: sender_2.1.k,
		sn: sender_2.2.sn,
		root: merkle_root_bytes,
	};
	let receiver_data_1 = ReceiverData {
		k: receiver_1.1.k,
		cm: receiver_1.0.cm_bytes,
		cipher: [0u8; 16],
	};
	let receiver_data_2 = ReceiverData {
		k: receiver_2.1.k,
		cm: receiver_2.0.cm_bytes,
		cipher: [0u8; 16],
	};

	println!("start benchmarking proof verification");
	let bench_str = format!("ZKP verification");
	let bench = Benchmark::new(bench_str, move |b| {
		b.iter(|| {
			assert!(manta_verify_transfer_zkp(
				TRANSFER_VKBYTES.to_vec(),
				proof_bytes,
				&sender_data_1,
				&sender_data_2,
				&receiver_data_1,
				&receiver_data_2,
			))
		})
	});

	// let bench = bench.sample_size(10);
	c.bench("transfer", bench);
}

fn bench_merkle_tree(c: &mut Criterion) {
	let hash_param_seed = HASH_PARAM_SEED;
	let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
	let hash_param = Hash::setup(&mut rng).unwrap();

	let mut cm_bytes1 = [0u8; 32];
	let cm_vec = BASE64
		.decode(b"XzoWOzhp6rXjQ/HDEN6jSLsLs64hKXWUNuFVtCUq0AA=")
		.unwrap();
	cm_bytes1.copy_from_slice(cm_vec[0..32].as_ref());

	let hash_param_clone = hash_param.clone();
	let bench_str = format!("with 1 leaf");
	let bench = Benchmark::new(bench_str, move |b| {
		b.iter(|| {
			merkle_root(hash_param_clone.clone(), &[cm_bytes1]);
		})
	});

	let mut cm_bytes2 = [0u8; 32];
	let cm_vec = BASE64
		.decode(b"3Oye4AqhzdysdWdCzMcoImTnYNGd21OmF8ztph4dRqI=")
		.unwrap();
	cm_bytes2.copy_from_slice(cm_vec[0..32].as_ref());

	let hash_param_clone = hash_param.clone();
	let bench_str = format!("with 2 leaf");
	let bench = bench.with_function(bench_str, move |b| {
		b.iter(|| {
			merkle_root(hash_param_clone.clone(), &[cm_bytes1, cm_bytes2]);
		})
	});

	let mut cm_bytes3 = [0u8; 32];
	let cm_vec = BASE64
		.decode(b"1zuOv92V7e1qX1bP7+QNsV+gW5E3xUsghte/lZ7h5pg=")
		.unwrap();
	cm_bytes3.copy_from_slice(cm_vec[0..32].as_ref());

	let bench_str = format!("with 3 leaf");
	let bench = bench.with_function(bench_str, move |b| {
		b.iter(|| {
			merkle_root(hash_param.clone(), &[cm_bytes1, cm_bytes2, cm_bytes3]);
		})
	});

	c.bench("merkle_tree", bench);
}

fn bench_pedersen_com(c: &mut Criterion) {
	let commit_param_seed = COMMIT_PARAM_SEED;
	let mut rng = ChaCha20Rng::from_seed(commit_param_seed);
	let param = CommitmentScheme::setup(&mut rng).unwrap();
	let bench_str = format!("commit open");
	let bench = Benchmark::new(bench_str, move |b| {
		b.iter(|| {
			let open = Randomness(Fr::deserialize([0u8; 32].as_ref()).unwrap());
			CommitmentScheme::commit(&param, [0u8; 32].as_ref(), &open).unwrap()
		})
	});

	c.bench("perdersen", bench);
}

fn bench_pedersen_hash(c: &mut Criterion) {
	let hash_param_seed = COMMIT_PARAM_SEED;
	let bench_str = format!("hash param gen");
	let bench = Benchmark::new(bench_str, move |b| {
		b.iter(|| {
			let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
			Hash::setup(&mut rng).unwrap();
		})
	});

	c.bench("perdersen", bench);
}

fn bench_transfer_prove(c: &mut Criterion) {
	let hash_param_seed = HASH_PARAM_SEED;
	let commit_param_seed = COMMIT_PARAM_SEED;

	let mut rng = ChaCha20Rng::from_seed(commit_param_seed);
	let commit_param = CommitmentScheme::setup(&mut rng).unwrap();

	let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
	let hash_param = Hash::setup(&mut rng).unwrap();

	let mut file = File::open("transfer_pk.bin").unwrap();
	let mut transfer_key_bytes: Vec<u8> = vec![];
	file.read_to_end(&mut transfer_key_bytes).unwrap();

	let pk = Groth16PK::deserialize_unchecked(transfer_key_bytes.as_ref()).unwrap();

	println!("proving key loaded from disk");

	// sender
	let mut sk = [0u8; 32];
	rng.fill_bytes(&mut sk);
	let sender_1 = make_coin(&commit_param, sk, 100, &mut rng);
	rng.fill_bytes(&mut sk);
	let sender_2 = make_coin(&commit_param, sk, 300, &mut rng);

	// receiver
	rng.fill_bytes(&mut sk);
	let receiver_1 = make_coin(&commit_param, sk, 150, &mut rng);
	rng.fill_bytes(&mut sk);
	let receiver_2 = make_coin(&commit_param, sk, 250, &mut rng);

	// merkle tree
	let tree = LedgerMerkleTree::new(
		hash_param.clone(),
		&[sender_1.0.cm_bytes, sender_2.0.cm_bytes],
	)
	.unwrap();
	let root = tree.root();
	let path_1 = tree.generate_proof(0, &sender_1.0.cm_bytes).unwrap();
	let path_2 = tree.generate_proof(1, &sender_2.0.cm_bytes).unwrap();

	let circuit = TransferCircuit {
		commit_param: commit_param.clone(),
		hash_param,

		sender_coin_1: sender_1.0.clone(),
		sender_pub_info_1: sender_1.1.clone(),
		sender_priv_info_1: sender_1.2.clone(),
		sender_membership_1: path_1.clone(),
		root_1: root.clone(),

		sender_coin_2: sender_2.0.clone(),
		sender_pub_info_2: sender_2.1.clone(),
		sender_priv_info_2: sender_2.2.clone(),
		sender_membership_2: path_2.clone(),
		root_2: root,

		receiver_coin_1: receiver_1.0.clone(),
		receiver_k_1: receiver_1.1.k,
		receiver_s_1: receiver_1.1.s,
		receiver_value_1: receiver_1.2.value,

		receiver_coin_2: receiver_2.0.clone(),
		receiver_k_2: receiver_2.1.k,
		receiver_s_2: receiver_2.1.s,
		receiver_value_2: receiver_2.2.value,
	};

	let bench_str = format!("ZKP proof generation");
	let bench = Benchmark::new(bench_str, move |b| {
		b.iter(|| {
			create_random_proof(circuit.clone(), &pk, &mut rng).unwrap();
		})
	});

	let bench = bench.sample_size(10);
	c.bench("transfer", bench);
}
