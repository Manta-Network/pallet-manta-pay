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

use crate::*;
use ark_bls12_381::Bls12_381;
use ark_ed_on_bls12_381::Fq;
use ark_ff::ToConstraintField;
use ark_groth16::{create_random_proof, generate_random_parameters, verify_proof};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalDeserialize;
use manta_api::{ReclaimCircuit, TransferCircuit};
use manta_asset::*;
use manta_crypto::{
	commitment_parameters, leaf_parameters, two_to_one_parameters, CommitmentOutput,
	CommitmentParam, Groth16Pk, Groth16Pvk, LeafHashParam, TwoToOneHashParam,
};
use manta_data::BuildMetadata;
use rand_chacha::{
	rand_core::{RngCore, SeedableRng},
	ChaCha20Rng,
};

/// this is a local test on zero knowledge proof generation and verifications
#[test]
fn test_transfer_zkp_local() {
	let leaf_param = leaf_parameters();
	let two_to_one_param = two_to_one_parameters();
	let commit_param = commitment_parameters();

	let mut rng = ChaCha20Rng::from_seed([3u8; 32]);

	// =============================
	// setup the circuit and the keys
	// =============================

	// sender
	let mut sk = [0u8; 32];
	rng.fill_bytes(&mut sk);
	let sender_1 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &100).unwrap();

	rng.fill_bytes(&mut sk);
	let sender_2 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &400).unwrap();

	// list of commitment
	let mut list = vec![sender_1.utxo, sender_2.utxo];
	for _e in 2..24 {
		let mut cm_rand = [0u8; 32];
		rng.fill_bytes(&mut cm_rand);
		list.push(cm_rand);
	}

	let sender_1 = sender_1
		.build(&leaf_param, &two_to_one_param, &list)
		.unwrap();
	let sender_2 = sender_2
		.build(&leaf_param, &two_to_one_param, &list)
		.unwrap();

	// receiver
	rng.fill_bytes(&mut sk);
	let receiver_1_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &()).unwrap();
	let receiver_1 = receiver_1_full
		.shielded_address
		.process(&240, &mut rng)
		.unwrap();

	rng.fill_bytes(&mut sk);
	let receiver_2_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &()).unwrap();
	let receiver_2 = receiver_2_full
		.shielded_address
		.process(&260, &mut rng)
		.unwrap();

	// build the circuit
	let circuit = TransferCircuit {
		commit_params: commit_param.clone(),
		leaf_params: leaf_param.clone(),
		two_to_one_params: two_to_one_param.clone(),
		senders: [sender_1, sender_2],
		receivers: [receiver_1, receiver_2],
	};

	let sanity_cs = ConstraintSystem::<Fq>::new_ref();
	circuit
		.clone()
		.generate_constraints(sanity_cs.clone())
		.unwrap();

	let re = sanity_cs.is_satisfied();
	match re {
		Ok(b) => assert!(b),
		Err(e) => {
			println!("Error: {:?}", e);
			assert!(false)
		}
	}

	// build the keys
	let pk = generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng).unwrap();

	// =============================
	// a normal test
	// =============================
	rng.fill_bytes(&mut sk);
	let sender_1 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &100).unwrap();
	rng.fill_bytes(&mut sk);
	let sender_2 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &400).unwrap();
	list.push(sender_1.utxo);
	list.push(sender_2.utxo);

	rng.fill_bytes(&mut sk);
	let receiver_1_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &()).unwrap();
	let receiver_1 = receiver_1_full
		.shielded_address
		.process(&240, &mut rng)
		.unwrap();

	rng.fill_bytes(&mut sk);
	let receiver_2_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &()).unwrap();
	let receiver_2 = receiver_2_full
		.shielded_address
		.process(&260, &mut rng)
		.unwrap();

	test_transfer_helper(
		commit_param.clone(),
		leaf_param.clone(),
		two_to_one_param.clone(),
		&pk,
		sender_1,
		sender_2,
		receiver_1,
		receiver_2,
		&list,
	);

	// =============================
	// test with a 0 sender token
	// =============================
	rng.fill_bytes(&mut sk);
	let sender_1 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &0).unwrap();
	rng.fill_bytes(&mut sk);
	let sender_2 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &500).unwrap();
	list.push(sender_1.utxo);
	list.push(sender_2.utxo);

	rng.fill_bytes(&mut sk);
	let receiver_1_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &()).unwrap();
	let receiver_1 = receiver_1_full
		.shielded_address
		.process(&300, &mut rng)
		.unwrap();

	rng.fill_bytes(&mut sk);
	let receiver_2_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &()).unwrap();
	let receiver_2 = receiver_2_full
		.shielded_address
		.process(&200, &mut rng)
		.unwrap();

	test_transfer_helper(
		commit_param.clone(),
		leaf_param.clone(),
		two_to_one_param.clone(),
		&pk,
		sender_1,
		sender_2,
		receiver_1,
		receiver_2,
		&list,
	);

	// =============================
	// test with a 0 receiver token
	// =============================
	rng.fill_bytes(&mut sk);
	let sender_1 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &111).unwrap();
	rng.fill_bytes(&mut sk);
	let sender_2 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &389).unwrap();
	list.push(sender_1.utxo);
	list.push(sender_2.utxo);

	rng.fill_bytes(&mut sk);
	let receiver_1_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &()).unwrap();
	let receiver_1 = receiver_1_full
		.shielded_address
		.process(&0, &mut rng)
		.unwrap();

	rng.fill_bytes(&mut sk);
	let receiver_2_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &()).unwrap();
	let receiver_2 = receiver_2_full
		.shielded_address
		.process(&500, &mut rng)
		.unwrap();

	test_transfer_helper(
		commit_param.clone(),
		leaf_param.clone(),
		two_to_one_param.clone(),
		&pk,
		sender_1,
		sender_2,
		receiver_1,
		receiver_2,
		&list,
	);

	// =============================
	// test with all 0 tokens
	// =============================
	rng.fill_bytes(&mut sk);
	let sender_1 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &0).unwrap();
	rng.fill_bytes(&mut sk);
	let sender_2 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &0).unwrap();
	list.push(sender_1.utxo);
	list.push(sender_2.utxo);

	rng.fill_bytes(&mut sk);
	let receiver_1_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &()).unwrap();
	let receiver_1 = receiver_1_full
		.shielded_address
		.process(&0, &mut rng)
		.unwrap();

	rng.fill_bytes(&mut sk);
	let receiver_2_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &()).unwrap();
	let receiver_2 = receiver_2_full
		.shielded_address
		.process(&0, &mut rng)
		.unwrap();

	test_transfer_helper(
		commit_param.clone(),
		leaf_param.clone(),
		two_to_one_param.clone(),
		&pk,
		sender_1,
		sender_2,
		receiver_1,
		receiver_2,
		&list,
	);
}

fn test_transfer_helper(
	commit_param: CommitmentParam,
	leaf_param: LeafHashParam,
	two_to_one_param: TwoToOneHashParam,
	pk: &Groth16Pk,
	sender_1: MantaAsset,
	sender_2: MantaAsset,
	receiver_1: MantaAssetProcessedReceiver,
	receiver_2: MantaAssetProcessedReceiver,
	list: &Vec<[u8; 32]>,
) {
	let mut rng = ChaCha20Rng::from_seed([8u8; 32]);

	let sender_1 = sender_1
		.build(&leaf_param, &two_to_one_param, list)
		.unwrap();
	let sender_2 = sender_2
		.build(&leaf_param, &two_to_one_param, list)
		.unwrap();

	let circuit = TransferCircuit {
		commit_params: commit_param.clone(),
		leaf_params: leaf_param.clone(),
		two_to_one_params: two_to_one_param.clone(),
		senders: [sender_1.clone(), sender_2.clone()],
		receivers: [receiver_1.clone(), receiver_2.clone()],
	};

	let sanity_cs = ConstraintSystem::<Fq>::new_ref();
	circuit
		.clone()
		.generate_constraints(sanity_cs.clone())
		.unwrap();
	assert!(sanity_cs.is_satisfied().unwrap());

	let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();

	let k_old_1 = CommitmentOutput::deserialize(sender_1.asset.pub_info.k.as_ref()).unwrap();
	let k_old_2 = CommitmentOutput::deserialize(sender_2.asset.pub_info.k.as_ref()).unwrap();
	let cm_new_1 = CommitmentOutput::deserialize(receiver_1.utxo.as_ref()).unwrap();
	let cm_new_2 = CommitmentOutput::deserialize(receiver_2.utxo.as_ref()).unwrap();

	// format the input to the verification
	let mut inputs = [
		k_old_1.x, k_old_1.y, // sender coin 3
		k_old_2.x, k_old_2.y, // sender coin 4
		cm_new_1.x, cm_new_1.y, // receiver coin 1
		cm_new_2.x, cm_new_2.y, // receiver coin 2
	]
	.to_vec();
	let sn_1: Vec<Fq> =
		ToConstraintField::<Fq>::to_field_elements(sender_1.asset.void_number.as_ref()).unwrap();
	let sn_2: Vec<Fq> =
		ToConstraintField::<Fq>::to_field_elements(sender_2.asset.void_number.as_ref()).unwrap();
	let mr: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&sender_1.root).unwrap();
	inputs = [
		inputs[..].as_ref(),
		sn_1.as_ref(),
		sn_2.as_ref(),
		mr.as_ref(),
		mr.as_ref(),
	]
	.concat();
	let pvk = Groth16Pvk::from(pk.vk.clone());
	assert!(verify_proof(&pvk, &proof, &inputs[..]).unwrap());
}

/// this is a local test on zero knowledge proof generation and verifications
#[test]
fn test_reclaim_zkp_local() {
	let leaf_param = leaf_parameters();
	let two_to_one_param = two_to_one_parameters();
	let commit_param = commitment_parameters();

	let mut rng = ChaCha20Rng::from_seed([3u8; 32]);

	// sender
	let mut sk = [0u8; 32];
	rng.fill_bytes(&mut sk);
	let sender_1 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &100).unwrap();
	rng.fill_bytes(&mut sk);
	let sender_2 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &400).unwrap();

	// receiver
	rng.fill_bytes(&mut sk);
	rng.fill_bytes(&mut sk);
	let receiver_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &()).unwrap();
	let receiver = receiver_full
		.shielded_address
		.process(&240, &mut rng)
		.unwrap();

	// list of commitment
	let mut list = vec![sender_1.utxo.clone(), sender_2.utxo.clone()];
	for _e in 1..24 {
		let mut cm_rand = [0u8; 32];
		rng.fill_bytes(&mut cm_rand);
		list.push(cm_rand);
	}

	let sender_1 = sender_1
		.build(&leaf_param, &two_to_one_param, &list)
		.unwrap();
	let sender_2 = sender_2
		.build(&leaf_param, &two_to_one_param, &list)
		.unwrap();

	// build the circuit
	let circuit = ReclaimCircuit {
		commit_params: commit_param.clone(),
		leaf_params: leaf_param.clone(),
		two_to_one_params: two_to_one_param.clone(),
		senders: [sender_1.clone(), sender_2.clone()],
		receiver: receiver,
		asset_id: sender_1.asset.asset_id,
		reclaim_value: 260,
	};

	let sanity_cs = ConstraintSystem::<Fq>::new_ref();
	circuit
		.clone()
		.generate_constraints(sanity_cs.clone())
		.unwrap();
	assert!(sanity_cs.is_satisfied().unwrap());

	let pk = generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng).unwrap();

	// =============================
	// a normal test
	// =============================

	rng.fill_bytes(&mut sk);
	let sender_1 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &100).unwrap();
	rng.fill_bytes(&mut sk);
	let sender_2 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &400).unwrap();
	list.push(sender_1.utxo);
	list.push(sender_2.utxo);

	rng.fill_bytes(&mut sk);
	let receiver_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &()).unwrap();
	let receiver = receiver_full
		.shielded_address
		.process(&300, &mut rng)
		.unwrap();

	test_reclaim_helper(
		commit_param.clone(),
		leaf_param.clone(),
		two_to_one_param.clone(),
		&pk,
		sender_1,
		sender_2,
		receiver,
		200,
		&list,
	);

	// =============================
	// test with a 0 sender token
	// =============================

	rng.fill_bytes(&mut sk);
	let sender_1 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &0).unwrap();
	rng.fill_bytes(&mut sk);
	let sender_2 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &500).unwrap();
	list.push(sender_1.utxo);
	list.push(sender_2.utxo);

	rng.fill_bytes(&mut sk);
	let receiver_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &()).unwrap();
	let receiver = receiver_full
		.shielded_address
		.process(&100, &mut rng)
		.unwrap();

	test_reclaim_helper(
		commit_param.clone(),
		leaf_param.clone(),
		two_to_one_param.clone(),
		&pk,
		sender_1,
		sender_2,
		receiver,
		400,
		&list,
	);

	// =============================
	// test with a 0 receiver token
	// =============================

	rng.fill_bytes(&mut sk);
	let sender_1 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &77).unwrap();
	rng.fill_bytes(&mut sk);
	let sender_2 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &423).unwrap();
	list.push(sender_1.utxo);
	list.push(sender_2.utxo);

	rng.fill_bytes(&mut sk);
	let receiver_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &()).unwrap();
	let receiver = receiver_full
		.shielded_address
		.process(&0, &mut rng)
		.unwrap();
	test_reclaim_helper(
		commit_param.clone(),
		leaf_param.clone(),
		two_to_one_param.clone(),
		&pk,
		sender_1,
		sender_2,
		receiver,
		500,
		&list,
	);

	// =============================
	// test with a 0 forfeit amount
	// =============================

	rng.fill_bytes(&mut sk);
	let sender_1 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &42).unwrap();
	rng.fill_bytes(&mut sk);
	let sender_2 = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &458).unwrap();
	list.push(sender_1.utxo);
	list.push(sender_2.utxo);

	rng.fill_bytes(&mut sk);
	let receiver_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &()).unwrap();
	let receiver = receiver_full
		.shielded_address
		.process(&500, &mut rng)
		.unwrap();

	test_reclaim_helper(
		commit_param.clone(),
		leaf_param.clone(),
		two_to_one_param.clone(),
		&pk,
		sender_1,
		sender_2,
		receiver,
		0,
		&list,
	);
}

fn test_reclaim_helper(
	commit_param: CommitmentParam,
	leaf_param: LeafHashParam,
	two_to_one_param: TwoToOneHashParam,
	pk: &Groth16Pk,
	sender_1: MantaAsset,
	sender_2: MantaAsset,
	receiver: MantaAssetProcessedReceiver,
	reclaim_value: AssetBalance,
	list: &Vec<[u8; 32]>,
) {
	let mut rng = ChaCha20Rng::from_seed([8u8; 32]);

	let sender_1 = sender_1
		.build(&leaf_param, &two_to_one_param, list)
		.unwrap();
	let sender_2 = sender_2
		.build(&leaf_param, &two_to_one_param, list)
		.unwrap();

	let circuit = ReclaimCircuit {
		commit_params: commit_param.clone(),
		leaf_params: leaf_param.clone(),
		two_to_one_params: two_to_one_param.clone(),
		senders: [sender_1.clone(), sender_2.clone()],
		receiver: receiver.clone(),
		asset_id: sender_1.asset.asset_id,
		reclaim_value,
	};

	let sanity_cs = ConstraintSystem::<Fq>::new_ref();
	circuit
		.clone()
		.generate_constraints(sanity_cs.clone())
		.unwrap();
	assert!(sanity_cs.is_satisfied().unwrap());

	let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();

	let k_old_1 = CommitmentOutput::deserialize(sender_1.asset.pub_info.k.as_ref()).unwrap();
	let k_old_2 = CommitmentOutput::deserialize(sender_2.asset.pub_info.k.as_ref()).unwrap();
	let cm_new = CommitmentOutput::deserialize(receiver.utxo.as_ref()).unwrap();

	// format the input to the verification
	let mut inputs = [
		k_old_1.x, k_old_1.y, // sender coin 3
		k_old_2.x, k_old_2.y, // sender coin 4
		cm_new.x, cm_new.y, // receiver coin 1
	]
	.to_vec();
	let sn_1: Vec<Fq> =
		ToConstraintField::<Fq>::to_field_elements(sender_1.asset.void_number.as_ref()).unwrap();
	let sn_2: Vec<Fq> =
		ToConstraintField::<Fq>::to_field_elements(sender_2.asset.void_number.as_ref()).unwrap();
	let mr: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&sender_1.root).unwrap();
	let reclaim_value_fq = Fq::from(reclaim_value);
	let asset_id_fq = Fq::from(sender_1.asset.asset_id as u64);
	inputs = [
		inputs[..].as_ref(),
		sn_1.as_ref(),
		sn_2.as_ref(),
		mr.as_ref(),
		mr.as_ref(),
		&[reclaim_value_fq],
		&[asset_id_fq],
	]
	.concat();
	let pvk = Groth16Pvk::from(pk.vk.clone());
	assert!(verify_proof(&pvk, &proof, &inputs[..]).unwrap());
}
