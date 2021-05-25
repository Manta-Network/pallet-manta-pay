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
use ark_std::rand::{RngCore, SeedableRng};
use criterion::Criterion;
use data_encoding::BASE64;
use manta_asset::*;
use manta_crypto::*;
use pallet_manta_pay::*;
use rand_chacha::ChaCha20Rng;
use std::{fs::File, io::prelude::*};

criterion_group!(
	manta_bench,
	bench_param_io,
	bench_pedersen_hash,
	bench_pedersen_com,
	bench_merkle_tree,
	bench_transfer_verify,
	bench_reclaim_verify,
	bench_transfer_prove,
	bench_reclaim_prove
);
criterion_main!(manta_bench);

fn bench_param_io(c: &mut Criterion) {
	let mut bench_group = c.benchmark_group("param deserialization");

	let bench_str = format!("hash param");
	bench_group.bench_function(bench_str, move |b| {
		b.iter(|| {
			HashParam::deserialize(HASH_PARAM.data).unwrap();
		})
	});

	let bench_str = format!("commit param");
	bench_group.bench_function(bench_str, move |b| {
		b.iter(|| {
			CommitmentParam::deserialize(COMMIT_PARAM.data).unwrap();
		})
	});
	bench_group.finish();
}

fn bench_transfer_verify(c: &mut Criterion) {
	let hash_param_seed = HASH_PARAM_SEED;
	let commit_param_seed = COMMIT_PARAM_SEED;

	let mut rng = ChaCha20Rng::from_seed(commit_param_seed);
	let commit_param = CommitmentScheme::setup(&mut rng).unwrap();

	let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
	let hash_param = Hash::setup(&mut rng).unwrap();

	let mut file = File::open("transfer_pk.bin").unwrap();
	let mut transfer_key_bytes: Vec<u8> = vec![];
	file.read_to_end(&mut transfer_key_bytes).unwrap();
	let buf: &[u8] = transfer_key_bytes.as_ref();
	let pk = Groth16Pk::deserialize_unchecked(buf).unwrap();

	println!("proving key loaded from disk");

	// sender
	let mut sk = [0u8; 32];
	rng.fill_bytes(&mut sk);
	let sender_1 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &100, &mut rng).unwrap();

	rng.fill_bytes(&mut sk);
	let sender_2 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &300, &mut rng).unwrap();

	let list = [sender_1.commitment, sender_2.commitment];
	let sender_1 = SenderMetaData::build(hash_param.clone(), sender_1, &list).unwrap();
	let sender_2 = SenderMetaData::build(hash_param.clone(), sender_2, &list).unwrap();

	// receiver
	rng.fill_bytes(&mut sk);
	let receiver_1_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &(), &mut rng).unwrap();
	let receiver_1 = receiver_1_full.prepared.process(&150, &mut rng).unwrap();

	rng.fill_bytes(&mut sk);
	let receiver_2_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &(), &mut rng).unwrap();
	let receiver_2 = receiver_2_full.prepared.process(&250, &mut rng).unwrap();

	let circuit = TransferCircuit {
		commit_param: commit_param.clone(),
		hash_param: hash_param.clone(),

		sender_1: sender_1.clone(),
		sender_2: sender_2.clone(),

		receiver_1: receiver_1.clone(),
		receiver_2: receiver_2.clone(),
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

	// form the transaction payload
	let transfer_data = generate_private_transfer_payload(
		commit_param.clone(),
		hash_param.clone(),
		&pk,
		sender_1,
		sender_2,
		receiver_1,
		receiver_2,
		&mut rng,
	)
	.unwrap();
	let transfer_data = PrivateTransferData::deserialize(transfer_data.as_ref()).unwrap();

	println!("start benchmarking proof verification");
	let mut bench_group = c.benchmark_group("private transfer");

	let bench_str = format!("ZKP verification");
	bench_group.bench_function(bench_str, move |b| {
		b.iter(|| assert!(transfer_data.verify(&TRANSFER_PK)))
	});

	bench_group.finish();
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

	let mut bench_group = c.benchmark_group("merkle tree");

	bench_group.bench_function(bench_str, move |b| {
		b.iter(|| {
			<MantaCrypto as MerkleTree>::root(hash_param_clone.clone(), &[cm_bytes1.clone()])
				.unwrap();
		})
	});

	let mut cm_bytes2 = [0u8; 32];
	let cm_vec = BASE64
		.decode(b"3Oye4AqhzdysdWdCzMcoImTnYNGd21OmF8ztph4dRqI=")
		.unwrap();
	cm_bytes2.copy_from_slice(cm_vec[0..32].as_ref());

	let hash_param_clone = hash_param.clone();
	let bench_str = format!("with 2 leaf");
	bench_group.bench_function(bench_str, move |b| {
		b.iter(|| {
			<MantaCrypto as MerkleTree>::root(
				hash_param_clone.clone(),
				&[cm_bytes1.clone(), cm_bytes2.clone()],
			)
			.unwrap();
		})
	});

	let mut cm_bytes3 = [0u8; 32];
	let cm_vec = BASE64
		.decode(b"1zuOv92V7e1qX1bP7+QNsV+gW5E3xUsghte/lZ7h5pg=")
		.unwrap();
	cm_bytes3.copy_from_slice(cm_vec[0..32].as_ref());

	let hash_param_clone = hash_param.clone();
	let bench_str = format!("with 3 leaf");
	bench_group.bench_function(bench_str, move |b| {
		b.iter(|| {
			<MantaCrypto as MerkleTree>::root(
				hash_param_clone.clone(),
				&[cm_bytes1.clone(), cm_bytes2.clone(), cm_bytes3.clone()],
			)
			.unwrap();
		})
	});

	bench_group.finish();
}

fn bench_pedersen_com(c: &mut Criterion) {
	let commit_param_seed = COMMIT_PARAM_SEED;
	let mut rng = ChaCha20Rng::from_seed(commit_param_seed);
	let param = CommitmentScheme::setup(&mut rng).unwrap();
	let bench_str = format!("commit open");

	let mut bench_group = c.benchmark_group("bench_pedersen_com");
	bench_group.bench_function(bench_str, move |b| {
		b.iter(|| {
			let open = Randomness(Fr::deserialize([0u8; 32].as_ref()).unwrap());
			CommitmentScheme::commit(&param, [0u8; 32].as_ref(), &open).unwrap()
		})
	});

	bench_group.finish()
}

fn bench_pedersen_hash(c: &mut Criterion) {
	let hash_param_seed = COMMIT_PARAM_SEED;
	let bench_str = format!("hash param gen");
	let mut bench_group = c.benchmark_group("bench_pedersen_hash");
	bench_group.bench_function(bench_str, move |b| {
		b.iter(|| {
			let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
			Hash::setup(&mut rng).unwrap();
		})
	});

	bench_group.finish()
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
	let buf: &[u8] = transfer_key_bytes.as_ref();
	let pk = Groth16Pk::deserialize_unchecked(buf).unwrap();

	println!("proving key loaded from disk");

	// sender
	let mut sk = [0u8; 32];
	rng.fill_bytes(&mut sk);
	let sender_1 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &100, &mut rng).unwrap();

	rng.fill_bytes(&mut sk);
	let sender_2 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &300, &mut rng).unwrap();

	let list = [sender_1.commitment, sender_2.commitment];
	let sender_1 = SenderMetaData::build(hash_param.clone(), sender_1, &list).unwrap();
	let sender_2 = SenderMetaData::build(hash_param.clone(), sender_2, &list).unwrap();

	// receiver
	rng.fill_bytes(&mut sk);
	let receiver_1_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &(), &mut rng).unwrap();
	let receiver_1 = receiver_1_full.prepared.process(&150, &mut rng).unwrap();

	rng.fill_bytes(&mut sk);
	let receiver_2_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &(), &mut rng).unwrap();
	let receiver_2 = receiver_2_full.prepared.process(&250, &mut rng).unwrap();

	let circuit = TransferCircuit {
		commit_param: commit_param.clone(),
		hash_param,

		sender_1: sender_1.clone(),
		sender_2: sender_2.clone(),

		receiver_1: receiver_1.clone(),
		receiver_2: receiver_2.clone(),
	};

	let mut bench_group = c.benchmark_group("private transfer");
	bench_group.sample_size(10);
	let bench_str = format!("ZKP proof generation");
	bench_group.bench_function(bench_str, move |b| {
		b.iter(|| {
			create_random_proof(circuit.clone(), &pk, &mut rng).unwrap();
		})
	});

	bench_group.finish();
}

fn bench_reclaim_verify(c: &mut Criterion) {
	let hash_param_seed = HASH_PARAM_SEED;
	let commit_param_seed = COMMIT_PARAM_SEED;

	let mut rng = ChaCha20Rng::from_seed(commit_param_seed);
	let commit_param = CommitmentScheme::setup(&mut rng).unwrap();

	let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
	let hash_param = Hash::setup(&mut rng).unwrap();

	let mut file = File::open("reclaim_pk.bin").unwrap();
	let mut reclaim_pk_bytes: Vec<u8> = vec![];
	file.read_to_end(&mut reclaim_pk_bytes).unwrap();
	let buf: &[u8] = reclaim_pk_bytes.as_ref();
	let pk = Groth16Pk::deserialize_unchecked(buf).unwrap();

	println!("proving key loaded from disk");

	// sender
	let mut sk = [0u8; 32];
	rng.fill_bytes(&mut sk);
	let sender_1 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &100, &mut rng).unwrap();

	rng.fill_bytes(&mut sk);
	let sender_2 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &300, &mut rng).unwrap();

	let list = [sender_1.commitment, sender_2.commitment];
	let sender_1 = SenderMetaData::build(hash_param.clone(), sender_1, &list).unwrap();
	let sender_2 = SenderMetaData::build(hash_param.clone(), sender_2, &list).unwrap();

	// receiver
	rng.fill_bytes(&mut sk);
	let receiver_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &(), &mut rng).unwrap();
	let receiver = receiver_full.prepared.process(&150, &mut rng).unwrap();

	let circuit = ReclaimCircuit {
		commit_param: commit_param.clone(),
		hash_param: hash_param.clone(),

		sender_1: sender_1.clone(),
		sender_2: sender_2.clone(),

		receiver: receiver.clone(),

		asset_id: TEST_ASSET,
		reclaim_value: 250,
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

	// form the transaction payload
	let reclaim_data = generate_reclaim_payload(
		commit_param.clone(),
		hash_param.clone(),
		&pk,
		sender_1,
		sender_2,
		receiver,
		250,
		&mut rng,
	)
	.unwrap();
	let reclaim_data = ReclaimData::deserialize(reclaim_data.as_ref()).unwrap();

	println!("start benchmarking proof verification");
	let mut bench_group = c.benchmark_group("reclaim");

	let bench_str = format!("ZKP verification");
	bench_group.bench_function(bench_str, move |b| {
		b.iter(|| assert!(reclaim_data.verify(&RECLAIM_PK)))
	});

	bench_group.finish();
}

fn bench_reclaim_prove(c: &mut Criterion) {
	let hash_param_seed = HASH_PARAM_SEED;
	let commit_param_seed = COMMIT_PARAM_SEED;

	let mut rng = ChaCha20Rng::from_seed(commit_param_seed);
	let commit_param = CommitmentScheme::setup(&mut rng).unwrap();

	let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
	let hash_param = Hash::setup(&mut rng).unwrap();

	let mut file = File::open("reclaim_pk.bin").unwrap();
	let mut reclaim_pk_bytes: Vec<u8> = vec![];
	file.read_to_end(&mut reclaim_pk_bytes).unwrap();
	let buf: &[u8] = reclaim_pk_bytes.as_ref();
	let pk = Groth16Pk::deserialize_unchecked(buf).unwrap();

	println!("proving key loaded from disk");

	// sender
	let mut sk = [0u8; 32];
	rng.fill_bytes(&mut sk);
	let sender_1 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &100, &mut rng).unwrap();

	rng.fill_bytes(&mut sk);
	let sender_2 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &300, &mut rng).unwrap();

	let list = [sender_1.commitment, sender_2.commitment];
	let sender_1 = SenderMetaData::build(hash_param.clone(), sender_1, &list).unwrap();
	let sender_2 = SenderMetaData::build(hash_param.clone(), sender_2, &list).unwrap();

	// receiver
	rng.fill_bytes(&mut sk);
	let receiver_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &(), &mut rng).unwrap();
	let receiver = receiver_full.prepared.process(&150, &mut rng).unwrap();

	let circuit = ReclaimCircuit {
		commit_param: commit_param.clone(),
		hash_param: hash_param.clone(),

		sender_1: sender_1.clone(),
		sender_2: sender_2.clone(),

		receiver: receiver.clone(),

		asset_id: TEST_ASSET,
		reclaim_value: 250,
	};

	let sanity_cs = ConstraintSystem::<Fq>::new_ref();
	circuit
		.clone()
		.generate_constraints(sanity_cs.clone())
		.unwrap();
	assert!(sanity_cs.is_satisfied().unwrap());

	let mut bench_group = c.benchmark_group("reclaim");
	bench_group.sample_size(10);
	let bench_str = format!("ZKP proof generation");
	bench_group.bench_function(bench_str, move |b| {
		b.iter(|| {
			create_random_proof(circuit.clone(), &pk, &mut rng).unwrap();
		})
	});

	bench_group.finish();
}
