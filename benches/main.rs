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
	commitment::pedersen::Randomness,
	crh::{TwoToOneCRH, CRH},
	CommitmentScheme as _,
};
use ark_ed_on_bls12_381::{Fq, Fr};
use ark_groth16::create_random_proof;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{RngCore, SeedableRng};
use criterion::Criterion;
use data_encoding::BASE64;
use manta_api::*;
use manta_asset::*;
use manta_crypto::*;
use manta_data::*;
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
	// TODO: let mut param = LEAF_PARAM.data;
	let mut param = HASH_PARAM.data;
	bench_group.bench_function("leaf params", move |b| {
		b.iter(|| {
			LeafHashParam::deserialize(&mut param).unwrap();
		})
	});
	// TODO: let mut param = TWO_TO_ONE_PARAM.data;
	let mut param = HASH_PARAM.data;
	bench_group.bench_function("two-to-one params", move |b| {
		b.iter(|| {
			TwoToOneHashParam::deserialize(&mut param).unwrap();
		})
	});
	let mut param = COMMIT_PARAM.data;
	bench_group.bench_function("commit params", move |b| {
		b.iter(|| {
			CommitmentParam::deserialize(&mut param).unwrap();
		})
	});
	bench_group.finish();
}

fn bench_transfer_verify(c: &mut Criterion) {
	let mut rng = ChaCha20Rng::from_seed(COMMIT_PARAM_SEED);
	let commit_params = CommitmentScheme::setup(&mut rng).unwrap();
	let mut rng = ChaCha20Rng::from_seed(LEAF_PARAM_SEED);
	let leaf_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
	let mut rng = ChaCha20Rng::from_seed(TWO_TO_ONE_PARAM_SEED);
	let two_to_one_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

	let mut file = File::open("transfer_pk.bin").unwrap();
	let mut transfer_key_bytes: Vec<u8> = vec![];
	file.read_to_end(&mut transfer_key_bytes).unwrap();
	let buf: &[u8] = transfer_key_bytes.as_ref();
	let pk = Groth16Pk::deserialize_unchecked(buf).unwrap();

	println!("proving key loaded from disk");

	// sender
	let mut sk = [0u8; 32];
	rng.fill_bytes(&mut sk);
	let sender_0 = MantaAsset::sample(&commit_params, &sk, &TEST_ASSET, &100).unwrap();

	rng.fill_bytes(&mut sk);
	let sender_1 = MantaAsset::sample(&commit_params, &sk, &TEST_ASSET, &300).unwrap();

	let list = vec![sender_0.utxo, sender_1.utxo];
	let sender_0 = sender_0
		.build(&leaf_params, &two_to_one_params, &list)
		.unwrap();
	let sender_1 = sender_1
		.build(&leaf_params, &two_to_one_params, &list)
		.unwrap();

	// receiver
	rng.fill_bytes(&mut sk);
	let receiver_0_full =
		MantaAssetFullReceiver::sample(&commit_params, &sk, &TEST_ASSET, &()).unwrap();
	let receiver_0 = receiver_0_full
		.shielded_address
		.process(&150, &mut rng)
		.unwrap();

	rng.fill_bytes(&mut sk);
	let receiver_1_full =
		MantaAssetFullReceiver::sample(&commit_params, &sk, &TEST_ASSET, &()).unwrap();
	let receiver_1 = receiver_1_full
		.shielded_address
		.process(&250, &mut rng)
		.unwrap();

	let circuit = TransferCircuit {
		commit_params: commit_params.clone(),
		leaf_params: leaf_params.clone(),
		two_to_one_params: two_to_one_params.clone(),
		senders: [sender_0.clone(), sender_1.clone()],
		receivers: [receiver_0.clone(), receiver_1.clone()],
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
	let transfer_data = generate_private_transfer_struct(
		commit_params.clone(),
		leaf_params.clone(),
		two_to_one_params.clone(),
		&pk,
		[sender_0, sender_1],
		[receiver_0, receiver_1],
		&mut rng,
	)
	.unwrap();
	// TODO[remove] let transfer_data = PrivateTransferData::deserialize(transfer_data).unwrap();

	println!("start benchmarking proof verification");
	let mut bench_group = c.benchmark_group("private transfer");
	bench_group.bench_function("ZKP verification", move |b| {
		b.iter(|| assert!(transfer_data.verify(&TRANSFER_VK)))
	});
	bench_group.finish();
}

fn bench_merkle_tree(c: &mut Criterion) {
	let mut rng = ChaCha20Rng::from_seed(LEAF_PARAM_SEED);
	let leaf_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
	let mut rng = ChaCha20Rng::from_seed(TWO_TO_ONE_PARAM_SEED);
	let two_to_one_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

	let mut cm_bytes0 = [0u8; 32];
	let cm_vec = BASE64
		.decode(b"XzoWOzhp6rXjQ/HDEN6jSLsLs64hKXWUNuFVtCUq0AA=")
		.unwrap();
	cm_bytes0.copy_from_slice(cm_vec[0..32].as_ref());

	let mut bench_group = c.benchmark_group("merkle tree");

	bench_group.bench_function("with 1 leaf", |b| {
		b.iter(|| {
			<MantaCrypto as MerkleTree>::root(
				&leaf_params,
				&two_to_one_params,
				&[cm_bytes0.clone()],
			)
			.unwrap();
		})
	});

	let mut cm_bytes1 = [0u8; 32];
	let cm_vec = BASE64
		.decode(b"3Oye4AqhzdysdWdCzMcoImTnYNGd21OmF8ztph4dRqI=")
		.unwrap();
	cm_bytes1.copy_from_slice(cm_vec[0..32].as_ref());

	bench_group.bench_function("with 2 leaves", |b| {
		b.iter(|| {
			<MantaCrypto as MerkleTree>::root(
				&leaf_params,
				&two_to_one_params,
				&[cm_bytes0.clone(), cm_bytes1.clone()],
			)
			.unwrap();
		})
	});

	let mut cm_bytes2 = [0u8; 32];
	let cm_vec = BASE64
		.decode(b"1zuOv92V7e1qX1bP7+QNsV+gW5E3xUsghte/lZ7h5pg=")
		.unwrap();
	cm_bytes2.copy_from_slice(cm_vec[0..32].as_ref());

	bench_group.bench_function("with 3 leaves", |b| {
		b.iter(|| {
			<MantaCrypto as MerkleTree>::root(
				&leaf_params,
				&two_to_one_params,
				&[cm_bytes0.clone(), cm_bytes1.clone(), cm_bytes2.clone()],
			)
			.unwrap();
		})
	});

	bench_group.finish();
}

fn bench_pedersen_com(c: &mut Criterion) {
	let mut rng = ChaCha20Rng::from_seed(COMMIT_PARAM_SEED);
	let commit_params = CommitmentScheme::setup(&mut rng).unwrap();
	let mut bench_group = c.benchmark_group("bench_pedersen_com");
	bench_group.bench_function("commit open", move |b| {
		b.iter(|| {
			let open = Randomness(Fr::deserialize([0u8; 32].as_ref()).unwrap());
			CommitmentScheme::commit(&commit_params, [0u8; 32].as_ref(), &open).unwrap()
		})
	});
	bench_group.finish()
}

fn bench_pedersen_hash(c: &mut Criterion) {
	let mut bench_group = c.benchmark_group("bench_pedersen_hash");
	bench_group.bench_function("hash param gen", move |b| {
		b.iter(|| {
			<LeafHash as CRH>::setup(&mut ChaCha20Rng::from_seed(LEAF_PARAM_SEED)).unwrap();
		})
	});
	bench_group.finish()
}

fn bench_transfer_prove(c: &mut Criterion) {
	let mut rng = ChaCha20Rng::from_seed(COMMIT_PARAM_SEED);
	let commit_params = CommitmentScheme::setup(&mut rng).unwrap();
	let mut rng = ChaCha20Rng::from_seed(LEAF_PARAM_SEED);
	let leaf_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
	let mut rng = ChaCha20Rng::from_seed(TWO_TO_ONE_PARAM_SEED);
	let two_to_one_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

	let mut file = File::open("transfer_pk.bin").unwrap();
	let mut transfer_key_bytes: Vec<u8> = vec![];
	file.read_to_end(&mut transfer_key_bytes).unwrap();
	let buf: &[u8] = transfer_key_bytes.as_ref();
	let pk = Groth16Pk::deserialize_unchecked(buf).unwrap();

	println!("proving key loaded from disk");

	// sender
	let mut sk = [0u8; 32];
	rng.fill_bytes(&mut sk);
	let sender_0 = MantaAsset::sample(&commit_params, &sk, &TEST_ASSET, &100).unwrap();

	rng.fill_bytes(&mut sk);
	let sender_1 = MantaAsset::sample(&commit_params, &sk, &TEST_ASSET, &300).unwrap();

	let list = vec![sender_0.utxo, sender_1.utxo];
	let sender_0 = sender_0
		.build(&leaf_params, &two_to_one_params, &list)
		.unwrap();
	let sender_1 = sender_1
		.build(&leaf_params, &two_to_one_params, &list)
		.unwrap();

	// receiver
	rng.fill_bytes(&mut sk);
	let receiver_0_full =
		MantaAssetFullReceiver::sample(&commit_params, &sk, &TEST_ASSET, &()).unwrap();
	let receiver_0 = receiver_0_full
		.shielded_address
		.process(&150, &mut rng)
		.unwrap();

	rng.fill_bytes(&mut sk);
	let receiver_1_full =
		MantaAssetFullReceiver::sample(&commit_params, &sk, &TEST_ASSET, &()).unwrap();
	let receiver_1 = receiver_1_full
		.shielded_address
		.process(&250, &mut rng)
		.unwrap();

	let circuit = TransferCircuit {
		commit_params,
		leaf_params,
		two_to_one_params,
		senders: [sender_0.clone(), sender_1.clone()],
		receivers: [receiver_0.clone(), receiver_1.clone()],
	};

	let mut bench_group = c.benchmark_group("private transfer");
	bench_group.sample_size(10);
	bench_group.bench_function("ZKP proof generation", move |b| {
		b.iter(|| {
			create_random_proof(circuit.clone(), &pk, &mut rng).unwrap();
		})
	});

	bench_group.finish();
}

fn bench_reclaim_verify(c: &mut Criterion) {
	let mut rng = ChaCha20Rng::from_seed(COMMIT_PARAM_SEED);
	let commit_params = CommitmentScheme::setup(&mut rng).unwrap();
	let mut rng = ChaCha20Rng::from_seed(LEAF_PARAM_SEED);
	let leaf_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
	let mut rng = ChaCha20Rng::from_seed(TWO_TO_ONE_PARAM_SEED);
	let two_to_one_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

	let mut file = File::open("reclaim_pk.bin").unwrap();
	let mut reclaim_pk_bytes: Vec<u8> = vec![];
	file.read_to_end(&mut reclaim_pk_bytes).unwrap();
	let buf: &[u8] = reclaim_pk_bytes.as_ref();
	let pk = Groth16Pk::deserialize_unchecked(buf).unwrap();

	println!("proving key loaded from disk");

	// sender
	let mut sk = [0u8; 32];
	rng.fill_bytes(&mut sk);
	let sender_0 = MantaAsset::sample(&commit_params, &sk, &TEST_ASSET, &100).unwrap();

	rng.fill_bytes(&mut sk);
	let sender_1 = MantaAsset::sample(&commit_params, &sk, &TEST_ASSET, &300).unwrap();

	let list = vec![sender_0.utxo, sender_1.utxo];
	let sender_0 = sender_0
		.build(&leaf_params, &two_to_one_params, &list)
		.unwrap();
	let sender_1 = sender_1
		.build(&leaf_params, &two_to_one_params, &list)
		.unwrap();

	// receiver
	rng.fill_bytes(&mut sk);
	let receiver_full =
		MantaAssetFullReceiver::sample(&commit_params, &sk, &TEST_ASSET, &()).unwrap();
	let receiver = receiver_full
		.shielded_address
		.process(&150, &mut rng)
		.unwrap();

	let circuit = ReclaimCircuit {
		commit_params: commit_params.clone(),
		leaf_params: leaf_params.clone(),
		two_to_one_params: two_to_one_params.clone(),
		senders: [sender_0.clone(), sender_1.clone()],
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
	let reclaim_data = generate_reclaim_struct(
		commit_params,
		leaf_params,
		two_to_one_params,
		&pk,
		[sender_0, sender_1],
		receiver,
		250,
		&mut rng,
	)
	.unwrap();
	// TODO[remove] let reclaim_data = ReclaimData::deserialize(&mut reclaim_data).unwrap();

	println!("start benchmarking proof verification");

	let mut bench_group = c.benchmark_group("reclaim");
	bench_group.bench_function("ZKP verification", move |b| {
		b.iter(|| assert!(reclaim_data.verify(&RECLAIM_VK)))
	});
	bench_group.finish();
}

fn bench_reclaim_prove(c: &mut Criterion) {
	let mut rng = ChaCha20Rng::from_seed(COMMIT_PARAM_SEED);
	let commit_params = CommitmentScheme::setup(&mut rng).unwrap();
	let mut rng = ChaCha20Rng::from_seed(LEAF_PARAM_SEED);
	let leaf_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
	let mut rng = ChaCha20Rng::from_seed(TWO_TO_ONE_PARAM_SEED);
	let two_to_one_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

	let mut file = File::open("reclaim_pk.bin").unwrap();
	let mut reclaim_pk_bytes: Vec<u8> = vec![];
	file.read_to_end(&mut reclaim_pk_bytes).unwrap();
	let buf: &[u8] = reclaim_pk_bytes.as_ref();
	let pk = Groth16Pk::deserialize_unchecked(buf).unwrap();

	println!("proving key loaded from disk");

	// sender
	let mut sk = [0u8; 32];
	rng.fill_bytes(&mut sk);
	let sender_0 = MantaAsset::sample(&commit_params, &sk, &TEST_ASSET, &100).unwrap();

	rng.fill_bytes(&mut sk);
	let sender_1 = MantaAsset::sample(&commit_params, &sk, &TEST_ASSET, &300).unwrap();

	let list = vec![sender_0.utxo, sender_1.utxo];
	let sender_0 = sender_0
		.build(&leaf_params, &two_to_one_params, &list)
		.unwrap();
	let sender_1 = sender_1
		.build(&leaf_params, &two_to_one_params, &list)
		.unwrap();

	// receiver
	rng.fill_bytes(&mut sk);
	let receiver_full =
		MantaAssetFullReceiver::sample(&commit_params, &sk, &TEST_ASSET, &()).unwrap();
	let receiver = receiver_full
		.shielded_address
		.process(&150, &mut rng)
		.unwrap();

	let circuit = ReclaimCircuit {
		commit_params,
		leaf_params,
		two_to_one_params,
		senders: [sender_0, sender_1],
		receiver,
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
	bench_group.bench_function("ZKP proof generation", move |b| {
		b.iter(|| {
			create_random_proof(circuit.clone(), &pk, &mut rng).unwrap();
		})
	});
	bench_group.finish();
}
