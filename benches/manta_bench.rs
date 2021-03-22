#[macro_use]
extern crate criterion;
extern crate pallet_manta_dap;

use ark_crypto_primitives::{commitment::pedersen::Randomness, CommitmentScheme, FixedLengthCRH};
use ark_ed_on_bls12_381::{Fq, Fr};
use ark_groth16::create_random_proof;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use criterion::{Benchmark, Criterion};
use data_encoding::BASE64;
use pallet_manta_dap::{
	manta_token::*,
	param::*,
	priv_coin::*,
	serdes::{commit_param_deserialize, hash_param_deserialize},
	transfer::*,
};
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
	bench_trasnfer_verify,
);
criterion_main!(manta_bench);

fn bench_param_io(c: &mut Criterion) {
	let bench_str = format!("hash param");
	let bench = Benchmark::new(bench_str, move |b| {
		b.iter(|| {
			hash_param_deserialize(HASHPARAMBYTES.as_ref());
		})
	});

	let bench_str = format!("commit param");
	let bench = bench.with_function(bench_str, move |b| {
		b.iter(|| {
			commit_param_deserialize(COMPARAMBYTES.as_ref());
		})
	});

	// let bench = bench.sample_size(10);
	c.bench("deserialization", bench);
}

fn bench_trasnfer_verify(c: &mut Criterion) {
	let hash_param_seed = pallet_manta_dap::param::HASHPARAMSEED;
	let commit_param_seed = pallet_manta_dap::param::COMMITPARAMSEED;

	let mut rng = ChaCha20Rng::from_seed(commit_param_seed);
	let commit_param = MantaCoinCommitmentScheme::setup(&mut rng).unwrap();

	let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
	let hash_param = Hash::setup(&mut rng).unwrap();

	let mut file = File::open("transfer_pk.bin").unwrap();
	let mut transfer_key_bytes: Vec<u8> = vec![];
	file.read_to_end(&mut transfer_key_bytes).unwrap();
	let tmp: &[u8] = transfer_key_bytes.as_ref();
	let pk = Groth16PK::deserialize_uncompressed(tmp).unwrap();

	println!("proving key loaded from disk");

	// sender
	let mut sk = [0u8; 32];
	rng.fill_bytes(&mut sk);
	let (sender, sender_pub_info, sender_priv_info) = make_coin(&commit_param, sk, 100, &mut rng);

	// receiver
	let mut sk = [0u8; 32];
	rng.fill_bytes(&mut sk);
	let (receiver, receiver_pub_info, _receiver_priv_info) =
		make_coin(&commit_param, sk, 100, &mut rng);

	let circuit = TransferCircuit {
		commit_param,
		hash_param: hash_param.clone(),
		sender_coin: sender.clone(),
		sender_pub_info: sender_pub_info.clone(),
		sender_priv_info: sender_priv_info.clone(),
		receiver_coin: receiver.clone(),
		receiver_pub_info: receiver_pub_info.clone(),
		list: vec![sender.cm_bytes],
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

	let tree = LedgerMerkleTree::new(hash_param.clone(), &[sender.cm_bytes]).unwrap();
	let merkle_root = tree.root();
	let mut merkle_root_bytes = [0u8; 32];
	merkle_root.serialize(merkle_root_bytes.as_mut()).unwrap();

	println!("start benchmarking proof verification");
	let bench_str = format!("ZKP verification");
	let bench = Benchmark::new(bench_str, move |b| {
		b.iter(|| {
			assert!(manta_verify_transfer_zkp(
				pallet_manta_dap::param::TRANSFERVKBYTES.to_vec(),
				proof_bytes,
				sender_priv_info.sn,
				sender_pub_info.k,
				receiver_pub_info.k,
				receiver.cm_bytes,
				merkle_root_bytes,
			))
		})
	});

	// let bench = bench.sample_size(10);
	c.bench("transfer", bench);
}

fn bench_merkle_tree(c: &mut Criterion) {
	let hash_param_seed = pallet_manta_dap::param::HASHPARAMSEED;
	let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
	let hash_param = Hash::setup(&mut rng).unwrap();

	let mut cm_bytes = [0u8; 32];
	let cm_vec = BASE64
		.decode(b"XzoWOzhp6rXjQ/HDEN6jSLsLs64hKXWUNuFVtCUq0AA=")
		.unwrap();
	cm_bytes.copy_from_slice(cm_vec[0..32].as_ref());

	let coin1 = MantaCoin { cm_bytes: cm_bytes };
	let coin1_clone = coin1.clone();
	let hash_param_clone = hash_param.clone();
	let bench_str = format!("with 1 leaf");
	let bench = Benchmark::new(bench_str, move |b| {
		b.iter(|| {
			merkle_root(hash_param_clone.clone(), &[coin1_clone.clone()]);
		})
	});

	let mut cm_bytes = [0u8; 32];
	let cm_vec = BASE64
		.decode(b"3Oye4AqhzdysdWdCzMcoImTnYNGd21OmF8ztph4dRqI=")
		.unwrap();
	cm_bytes.copy_from_slice(cm_vec[0..32].as_ref());

	let coin2 = MantaCoin { cm_bytes: cm_bytes };

	let coin1_clone = coin1.clone();
	let coin2_clone = coin2.clone();
	let hash_param_clone = hash_param.clone();
	let bench_str = format!("with 2 leaf");
	let bench = bench.with_function(bench_str, move |b| {
		b.iter(|| {
			merkle_root(
				hash_param_clone.clone(),
				&[coin1_clone.clone(), coin2_clone.clone()],
			);
		})
	});

	let mut cm_bytes = [0u8; 32];
	let cm_vec = BASE64
		.decode(b"1zuOv92V7e1qX1bP7+QNsV+gW5E3xUsghte/lZ7h5pg=")
		.unwrap();
	cm_bytes.copy_from_slice(cm_vec[0..32].as_ref());

	let coin3 = MantaCoin { cm_bytes: cm_bytes };

	let bench_str = format!("with 3 leaf");
	let bench = bench.with_function(bench_str, move |b| {
		b.iter(|| {
			merkle_root(
				hash_param.clone(),
				&[coin1.clone(), coin2.clone(), coin3.clone()],
			);
		})
	});

	c.bench("merkle_tree", bench);
}

fn bench_pedersen_com(c: &mut Criterion) {
	let commit_param_seed = pallet_manta_dap::param::COMMITPARAMSEED;
	let mut rng = ChaCha20Rng::from_seed(commit_param_seed);
	let param = MantaCoinCommitmentScheme::setup(&mut rng).unwrap();
	let bench_str = format!("commit open");
	let bench = Benchmark::new(bench_str, move |b| {
		b.iter(|| {
			let open = Randomness(Fr::deserialize([0u8; 32].as_ref()).unwrap());
			MantaCoinCommitmentScheme::commit(&param, [0u8; 32].as_ref(), &open).unwrap()
		})
	});

	c.bench("perdersen", bench);
}

fn bench_pedersen_hash(c: &mut Criterion) {
	let hash_param_seed = pallet_manta_dap::param::COMMITPARAMSEED;
	let bench_str = format!("hash param gen");
	let bench = Benchmark::new(bench_str, move |b| {
		b.iter(|| {
			let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
			Hash::setup(&mut rng).unwrap();
		})
	});

	c.bench("perdersen", bench);
}
