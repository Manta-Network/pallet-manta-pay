use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{CommitmentScheme, FixedLengthCRH};
use ark_ed_on_bls12_381::Fq;
use ark_groth16::{create_random_proof, generate_random_parameters};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use data_encoding::BASE64;
use pallet_manta_dap::{
	dh::*, manta_token::*, param::*, priv_coin::*, reclaim::*, serdes::*, shard::*, transfer::*,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{fs::File, io::prelude::*};
use x25519_dalek::{PublicKey, StaticSecret};

fn main() {
	println!("Hello, Manta!");

	let hash_param_seed = [1u8; 32];
	let commit_param_seed = [2u8; 32];

	let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
	let hash_param = Hash::setup(&mut rng).unwrap();

	let mut rng = ChaCha20Rng::from_seed(commit_param_seed);
	let commit_param = MantaCoinCommitmentScheme::setup(&mut rng).unwrap();

	let size = 1_000usize;
	let mut shards = Shards::default();
	for i in 0..size {
		let value = i as u64 + 10;
		let (coin, pub_info, priv_info) = make_coin(&commit_param, [0u8; 32], value, &mut rng);

		shards.update(&coin.cm_bytes, hash_param.clone());
		let mint_data = [coin.cm_bytes, pub_info.k, pub_info.s].concat();
		let sender_data = [pub_info.k, priv_info.sn].concat();

		let (coin, pub_info, _priv_info) = make_coin(&commit_param, [0u8; 32], value, &mut rng);
		let receiver_data = [
			pub_info.k.as_ref(),
			coin.cm_bytes.as_ref(),
			[0u8; 16].as_ref(),
		]
		.concat();

		let file_str = format!("tmp/mint/{}.bin", i);
		let mut file = File::create(file_str).unwrap();
		file.write_all(mint_data.as_ref()).unwrap();

		let file_str = format!("tmp/sender/{}.bin", i);
		let mut file = File::create(file_str).unwrap();
		file.write_all(sender_data.as_ref()).unwrap();

		let file_str = format!("tmp/receiver/{}.bin", i);
		let mut file = File::create(file_str).unwrap();
		file.write_all(receiver_data.as_ref()).unwrap();
	}


	for i in 0..256 {
		let file_str = format!("tmp/shards/{}.bin", i);
		let mut file = File::create(file_str).unwrap();
		file.write_all(shards.shard[i].root.as_ref()).unwrap();
	}

	
}
