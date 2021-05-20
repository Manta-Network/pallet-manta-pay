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
use ark_crypto_primitives::{CommitmentScheme as ArkCommitmentScheme, FixedLengthCRH};
use ark_ed_on_bls12_381::Fq;
use ark_groth16::generate_random_parameters;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{RngCore, SeedableRng};
use hkdf::Hkdf;
use manta_crypto::*;
use pallet_manta_asset::*;
use rand_chacha::ChaCha20Rng;
use sha2::Sha512Trunc256;
use std::{fs::File, io::prelude::*};

/// Generate the ZKP keys with a default seed, and write to
/// `transfer_pk.bin` and `reclaim_pk.bin`.
pub fn write_zkp_keys() {
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

// Generate ZKP keys for `private_transfer` circuit.
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

		let sender = MantaAsset::sample(
			&commit_param,
			&sk,
			&AssetId::TestAsset,
			&(e + 100),
			&mut rng,
		);
		ledger.push(sender.commitment);
		coins.push(sender);
	}

	// sender's total value is 210
	let sender_1 = coins[0].clone();
	let sender_2 = coins[10].clone();

	let sender_1 = SenderMetaData::build(hash_param.clone(), sender_1, &ledger);
	let sender_2 = SenderMetaData::build(hash_param.clone(), sender_2, &ledger);

	// receiver's total value is also 210
	rng.fill_bytes(&mut sk);
	let receiver_1_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &AssetId::TestAsset, &(), &mut rng);
	let receiver_1 = receiver_1_full.prepared.process(&80, &mut rng);
	rng.fill_bytes(&mut sk);
	let receiver_2_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &AssetId::TestAsset, &(), &mut rng);
	let receiver_2 = receiver_2_full.prepared.process(&130, &mut rng);

	// transfer circuit
	let transfer_circuit = TransferCircuit {
		// param
		commit_param,
		hash_param,

		// sender
		sender_1,
		sender_2,

		// receiver
		receiver_1,
		receiver_2,
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
	transfer_vk.serialize_uncompressed(&mut vk_buf).unwrap();
	println!("pk_uncompressed len {}", transfer_pk_bytes.len());
	println!("vk: {:?}", vk_buf);

	pk.serialize_uncompressed(&mut transfer_pk_bytes).unwrap();
	transfer_pk_bytes
}

// Generate ZKP keys for `reclaim` circuit.
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

		let sender = MantaAsset::sample(
			&commit_param,
			&sk,
			&AssetId::TestAsset,
			&(e + 100),
			&mut rng,
		);
		ledger.push(sender.commitment);
		coins.push(sender);
	}
	// sender's total value is 210
	let sender_1 = coins[0].clone();
	let sender_2 = coins[10].clone();

	let sender_1 = SenderMetaData::build(hash_param.clone(), sender_1, &ledger);
	let sender_2 = SenderMetaData::build(hash_param.clone(), sender_2, &ledger);

	// receiver's total value is also 210
	let receiver_full =
		MantaAssetFullReceiver::sample(&commit_param, &sk, &AssetId::TestAsset, &(), &mut rng);
	let receiver = receiver_full.prepared.process(&80, &mut rng);

	// transfer circuit
	let reclaim_circuit = ReclaimCircuit {
		// param
		commit_param,
		hash_param,

		// sender
		sender_1,
		sender_2,

		// receiver
		receiver,

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
	reclaim_vk.serialize_uncompressed(&mut vk_buf).unwrap();
	println!("pk_uncompressed len {}", reclaim_pk_bytes.len());
	println!("vk: {:?}", vk_buf);

	pk.serialize_uncompressed(&mut reclaim_pk_bytes).unwrap();
	reclaim_pk_bytes
}
