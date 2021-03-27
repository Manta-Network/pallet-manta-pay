use crate::{coin::*, param, serdes::*, *};
use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{CommitmentScheme, FixedLengthCRH};
use ark_ed_on_bls12_381::Fq;
use ark_ff::ToConstraintField;
use ark_groth16::{create_random_proof, generate_random_parameters, verify_proof};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalDeserialize;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use x25519_dalek::{PublicKey, StaticSecret};

/// this is a local test on zero knowledge proof generation and verifications
#[test]
fn test_transfer_zkp_local() {
	let hash_param = HashParam::deserialize(HASHPARAMBYTES.as_ref());
	let commit_param = CommitmentParam::deserialize(COMPARAMBYTES.as_ref());

	let mut rng = ChaCha20Rng::from_seed([3u8; 32]);

	// sender
	let mut sk = [0u8; 32];
	rng.fill_bytes(&mut sk);
	let (sender_1, sender_pub_info_1, sender_priv_info_1) =
		make_coin(&commit_param, sk, 100, &mut rng);

	rng.fill_bytes(&mut sk);
	let (sender_2, sender_pub_info_2, sender_priv_info_2) =
		make_coin(&commit_param, sk, 400, &mut rng);

	// receiver
	rng.fill_bytes(&mut sk);
	let (receiver_1, receiver_pub_info_1, _receiver_priv_info_1) =
		make_coin(&commit_param, sk, 240, &mut rng);

	rng.fill_bytes(&mut sk);
	let (receiver_2, receiver_pub_info_2, _receiver_priv_info_2) =
		make_coin(&commit_param, sk, 260, &mut rng);

	// list of commitment
	let mut list = vec![sender_1.cm_bytes.clone(), sender_2.cm_bytes.clone()];
	for _e in 2..24 {
		let mut cm_rand = [0u8; 32];
		rng.fill_bytes(&mut cm_rand);
		list.push(cm_rand);
	}
	let tree = param::LedgerMerkleTree::new(hash_param.clone(), &list).unwrap();
	let merkle_root = tree.root();

	let circuit = crypto::TransferCircuit {
		commit_param: commit_param.clone(),
		hash_param: hash_param.clone(),

		sender_coin_1: sender_1.clone(),
		sender_pub_info_1: sender_pub_info_1.clone(),
		sender_priv_info_1: sender_priv_info_1.clone(),

		sender_coin_2: sender_2.clone(),
		sender_pub_info_2: sender_pub_info_2.clone(),
		sender_priv_info_2: sender_priv_info_2.clone(),

		receiver_coin_1: receiver_1.clone(),
		receiver_pub_info_1: receiver_pub_info_1.clone(),
		receiver_value_1: 240,

		receiver_coin_2: receiver_2.clone(),
		receiver_pub_info_2: receiver_pub_info_2.clone(),
		receiver_value_2: 260,

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
	let pvk = param::Groth16PVK::from(pk.vk.clone());

	let k_old_1 = param::CommitmentOutput::deserialize(sender_pub_info_1.k.as_ref()).unwrap();
	let k_old_2 = param::CommitmentOutput::deserialize(sender_pub_info_2.k.as_ref()).unwrap();
	let k_new_1 = param::CommitmentOutput::deserialize(receiver_pub_info_1.k.as_ref()).unwrap();
	let k_new_2 = param::CommitmentOutput::deserialize(receiver_pub_info_2.k.as_ref()).unwrap();
	let cm_new_1 = param::CommitmentOutput::deserialize(receiver_1.cm_bytes.as_ref()).unwrap();
	let cm_new_2 = param::CommitmentOutput::deserialize(receiver_2.cm_bytes.as_ref()).unwrap();

	// format the input to the verification
	let mut inputs = [
		k_old_1.x, k_old_1.y, // sender coin 1
		k_old_2.x, k_old_2.y, // sender coin 2
		k_new_1.x, k_new_1.y, cm_new_1.x, cm_new_1.y, // receiver coin 1
		k_new_2.x, k_new_2.y, cm_new_2.x, cm_new_2.y, // receiver coin 2
	]
	.to_vec();
	let sn_1: Vec<Fq> =
		ToConstraintField::<Fq>::to_field_elements(sender_priv_info_1.sn.as_ref()).unwrap();
	let sn_2: Vec<Fq> =
		ToConstraintField::<Fq>::to_field_elements(sender_priv_info_2.sn.as_ref()).unwrap();
	let mr: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&merkle_root).unwrap();
	inputs = [
		inputs[..].as_ref(),
		sn_1.as_ref(),
		sn_2.as_ref(),
		mr.as_ref(),
	]
	.concat();

	// println!("{} {}", inputs.len(), pvk.vk.gamma_abc_g1.len());
	assert!(verify_proof(&pvk, &proof, &inputs[..]).unwrap());

	// ==========================================
	// with a new sender at another position of the leaf
	// ==========================================

	rng.fill_bytes(&mut sk);
	let (sender_3, sender_pub_info_3, sender_priv_info_3) =
		make_coin(&commit_param, sk, 1, &mut rng);
	list.push(sender_3.cm_bytes);
	rng.fill_bytes(&mut sk);
	let (sender_4, sender_pub_info_4, sender_priv_info_4) =
		make_coin(&commit_param, sk, 499, &mut rng);
	list.push(sender_4.cm_bytes);
	let tree = param::LedgerMerkleTree::new(hash_param.clone(), &list).unwrap();
	let merkle_root = tree.root();

	let circuit = crypto::TransferCircuit {
		commit_param: commit_param.clone(),
		hash_param,
		sender_coin_1: sender_3.clone(),
		sender_pub_info_1: sender_pub_info_3.clone(),
		sender_priv_info_1: sender_priv_info_3.clone(),
		sender_coin_2: sender_4.clone(),
		sender_pub_info_2: sender_pub_info_4.clone(),
		sender_priv_info_2: sender_priv_info_4.clone(),
		receiver_coin_1: receiver_1.clone(),
		receiver_pub_info_1: receiver_pub_info_1.clone(),
		receiver_value_1: 240,
		receiver_coin_2: receiver_2.clone(),
		receiver_pub_info_2: receiver_pub_info_2.clone(),
		receiver_value_2: 260,
		list,
	};

	let sanity_cs = ConstraintSystem::<Fq>::new_ref();
	circuit
		.clone()
		.generate_constraints(sanity_cs.clone())
		.unwrap();
	assert!(sanity_cs.is_satisfied().unwrap());

	let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();

	let k_old_1 = param::CommitmentOutput::deserialize(sender_pub_info_3.k.as_ref()).unwrap();
	let k_old_2 = param::CommitmentOutput::deserialize(sender_pub_info_4.k.as_ref()).unwrap();
	let k_new_1 = param::CommitmentOutput::deserialize(receiver_pub_info_1.k.as_ref()).unwrap();
	let k_new_2 = param::CommitmentOutput::deserialize(receiver_pub_info_2.k.as_ref()).unwrap();
	let cm_new_1 = param::CommitmentOutput::deserialize(receiver_1.cm_bytes.as_ref()).unwrap();
	let cm_new_2 = param::CommitmentOutput::deserialize(receiver_2.cm_bytes.as_ref()).unwrap();

	// format the input to the verification
	let mut inputs = [
		k_old_1.x, k_old_1.y, // sender coin 3
		k_old_2.x, k_old_2.y, // sender coin 4
		k_new_1.x, k_new_1.y, cm_new_1.x, cm_new_1.y, // receiver coin 1
		k_new_2.x, k_new_2.y, cm_new_2.x, cm_new_2.y, // receiver coin 2
	]
	.to_vec();
	let sn_1: Vec<Fq> =
		ToConstraintField::<Fq>::to_field_elements(sender_priv_info_3.sn.as_ref()).unwrap();
	let sn_2: Vec<Fq> =
		ToConstraintField::<Fq>::to_field_elements(sender_priv_info_4.sn.as_ref()).unwrap();
	let mr: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&merkle_root).unwrap();
	inputs = [
		inputs[..].as_ref(),
		sn_1.as_ref(),
		sn_2.as_ref(),
		mr.as_ref(),
	]
	.concat();

	assert!(verify_proof(&pvk, &proof, &inputs[..]).unwrap());
}

/// this is a local test on zero knowledge proof generation and verifications
#[test]
fn test_reclaim_zkp_local() {
	let hash_param = HashParam::deserialize(HASHPARAMBYTES.as_ref());
	let commit_param = CommitmentParam::deserialize(COMPARAMBYTES.as_ref());

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
	let tree = param::LedgerMerkleTree::new(hash_param.clone(), &list).unwrap();
	let merkle_root = tree.root();

	let circuit = crypto::ReclaimCircuit {
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
	let pvk = param::Groth16PVK::from(pk.vk.clone());

	let k_old = param::CommitmentOutput::deserialize(sender_pub_info.k.as_ref()).unwrap();

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

#[test]
fn manta_dh() {
	let mut rng = rand::thread_rng();
	let receiver_sk = StaticSecret::new(rng);
	let receiver_pk = PublicKey::from(&receiver_sk);
	let receiver_pk_bytes = receiver_pk.to_bytes();
	let receiver_sk_bytes = receiver_sk.to_bytes();
	let value = 12345678;
	let (sender_pk_bytes, cipher) = crypto::manta_dh_enc(&receiver_pk_bytes, value, &mut rng);
	println!("enc success");
	let rec_value = crypto::manta_dh_dec(&cipher, &sender_pk_bytes, &receiver_sk_bytes);
	assert_eq!(value, rec_value);
}

#[test]
fn test_param_serdes() {
	let hash_param_seed = [1u8; 32];
	let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
	let hash_param = param::Hash::setup(&mut rng).unwrap();
	let mut buf: Vec<u8> = vec![];

	hash_param.serialize(&mut buf);
	let hash_param2 = HashParam::deserialize(buf.as_ref());
	assert_eq!(hash_param.generators, hash_param2.generators);

	let commit_param_seed = [2u8; 32];
	let mut rng = ChaCha20Rng::from_seed(commit_param_seed);
	let commit_param = param::CommitmentScheme::setup(&mut rng).unwrap();
	let mut buf: Vec<u8> = vec![];

	commit_param.serialize(&mut buf);
	let commit_param2 = CommitmentParam::deserialize(buf.as_ref());
	assert_eq!(commit_param.generators, commit_param2.generators);
	assert_eq!(
		commit_param.randomness_generator,
		commit_param2.randomness_generator
	);
}
