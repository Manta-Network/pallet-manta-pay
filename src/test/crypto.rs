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
	let hash_param = HashParam::deserialize(HASH_PARAM_BYTES.as_ref());
	let commit_param = CommitmentParam::deserialize(COMMIT_PARAM_BYTES.as_ref());

	let mut rng = ChaCha20Rng::from_seed([3u8; 32]);

	// =============================
	// setup the circuit and the keys
	// =============================

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

	let index_1 = list.iter().position(|x| *x == sender_1.cm_bytes).unwrap();
	let path_1 = tree.generate_proof(index_1, &sender_1.cm_bytes).unwrap();

	let index_2 = list.iter().position(|x| *x == sender_2.cm_bytes).unwrap();
	let path_2 = tree.generate_proof(index_2, &sender_2.cm_bytes).unwrap();

	// build the circuit
	let circuit = crypto::TransferCircuit {
		commit_param: commit_param.clone(),
		hash_param: hash_param.clone(),

		sender_coin_1: sender_1.clone(),
		sender_pub_info_1: sender_pub_info_1.clone(),
		sender_priv_info_1: sender_priv_info_1.clone(),
		sender_membership_1: path_1,
		root_1: merkle_root.clone(),

		sender_coin_2: sender_2.clone(),
		sender_pub_info_2: sender_pub_info_2.clone(),
		sender_priv_info_2: sender_priv_info_2.clone(),
		sender_membership_2: path_2,
		root_2: merkle_root,

		receiver_coin_1: receiver_1.clone(),
		receiver_k_1: receiver_pub_info_1.k,
		receiver_s_1: receiver_pub_info_1.s,
		receiver_value_1: 240,

		receiver_coin_2: receiver_2.clone(),
		receiver_k_2: receiver_pub_info_2.k,
		receiver_s_2: receiver_pub_info_2.s,
		receiver_value_2: 260,
	};

	let sanity_cs = ConstraintSystem::<Fq>::new_ref();
	circuit
		.clone()
		.generate_constraints(sanity_cs.clone())
		.unwrap();
	assert!(sanity_cs.is_satisfied().unwrap());

	// build the keys
	let pk = generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng).unwrap();

	// =============================
	// a normal test
	// =============================
	rng.fill_bytes(&mut sk);
	let sender_1 = make_coin(&commit_param, sk, 100, &mut rng);
	rng.fill_bytes(&mut sk);
	let sender_2 = make_coin(&commit_param, sk, 400, &mut rng);
	list.push(sender_1.0.cm_bytes);
	list.push(sender_2.0.cm_bytes);

	rng.fill_bytes(&mut sk);
	let receiver_1 = make_coin(&commit_param, sk, 300, &mut rng);
	rng.fill_bytes(&mut sk);
	let receiver_2 = make_coin(&commit_param, sk, 200, &mut rng);

	test_transfer_helper(
		commit_param.clone(),
		hash_param.clone(),
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
	let sender_1 = make_coin(&commit_param, sk, 0, &mut rng);
	rng.fill_bytes(&mut sk);
	let sender_2 = make_coin(&commit_param, sk, 500, &mut rng);
	list.push(sender_1.0.cm_bytes);
	list.push(sender_2.0.cm_bytes);

	rng.fill_bytes(&mut sk);
	let receiver_1 = make_coin(&commit_param, sk, 300, &mut rng);
	rng.fill_bytes(&mut sk);
	let receiver_2 = make_coin(&commit_param, sk, 200, &mut rng);

	test_transfer_helper(
		commit_param.clone(),
		hash_param.clone(),
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
	let sender_1 = make_coin(&commit_param, sk, 111, &mut rng);
	rng.fill_bytes(&mut sk);
	let sender_2 = make_coin(&commit_param, sk, 389, &mut rng);
	list.push(sender_1.0.cm_bytes);
	list.push(sender_2.0.cm_bytes);

	rng.fill_bytes(&mut sk);
	let receiver_1 = make_coin(&commit_param, sk, 500, &mut rng);
	rng.fill_bytes(&mut sk);
	let receiver_2 = make_coin(&commit_param, sk, 0, &mut rng);

	test_transfer_helper(
		commit_param.clone(),
		hash_param.clone(),
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
	let sender_1 = make_coin(&commit_param, sk, 0, &mut rng);
	rng.fill_bytes(&mut sk);
	let sender_2 = make_coin(&commit_param, sk, 0, &mut rng);
	list.push(sender_1.0.cm_bytes);
	list.push(sender_2.0.cm_bytes);

	rng.fill_bytes(&mut sk);
	let receiver_1 = make_coin(&commit_param, sk, 0, &mut rng);
	rng.fill_bytes(&mut sk);
	let receiver_2 = make_coin(&commit_param, sk, 0, &mut rng);

	test_transfer_helper(
		commit_param.clone(),
		hash_param.clone(),
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
	hash_param: HashParam,
	pk: &Groth16PK,
	sender_1: (MantaCoin, MantaCoinPubInfo, MantaCoinPrivInfo),
	sender_2: (MantaCoin, MantaCoinPubInfo, MantaCoinPrivInfo),
	receiver_1: (MantaCoin, MantaCoinPubInfo, MantaCoinPrivInfo),
	receiver_2: (MantaCoin, MantaCoinPubInfo, MantaCoinPrivInfo),
	list: &[[u8; 32]],
) {
	let mut rng = ChaCha20Rng::from_seed([8u8; 32]);

	let tree = param::LedgerMerkleTree::new(hash_param.clone(), &list).unwrap();
	let merkle_root = tree.root();

	let index_1 = list.iter().position(|x| *x == sender_1.0.cm_bytes).unwrap();
	let path_1 = tree.generate_proof(index_1, &sender_1.0.cm_bytes).unwrap();

	let index_2 = list.iter().position(|x| *x == sender_2.0.cm_bytes).unwrap();
	let path_2 = tree.generate_proof(index_2, &sender_2.0.cm_bytes).unwrap();

	let circuit = crypto::TransferCircuit {
		commit_param: commit_param.clone(),
		hash_param,

		sender_coin_1: sender_1.0.clone(),
		sender_pub_info_1: sender_1.1.clone(),
		sender_priv_info_1: sender_1.2.clone(),
		sender_membership_1: path_1.clone(),
		root_1: merkle_root.clone(),

		sender_coin_2: sender_2.0.clone(),
		sender_pub_info_2: sender_2.1.clone(),
		sender_priv_info_2: sender_2.2.clone(),
		sender_membership_2: path_2.clone(),
		root_2: merkle_root,

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

	let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();

	let k_old_1 = param::CommitmentOutput::deserialize(sender_1.1.k.as_ref()).unwrap();
	let k_old_2 = param::CommitmentOutput::deserialize(sender_2.1.k.as_ref()).unwrap();
	let cm_new_1 = param::CommitmentOutput::deserialize(receiver_1.0.cm_bytes.as_ref()).unwrap();
	let cm_new_2 = param::CommitmentOutput::deserialize(receiver_2.0.cm_bytes.as_ref()).unwrap();

	// format the input to the verification
	let mut inputs = [
		k_old_1.x, k_old_1.y, // sender coin 3
		k_old_2.x, k_old_2.y, // sender coin 4
		cm_new_1.x, cm_new_1.y, // receiver coin 1
		cm_new_2.x, cm_new_2.y, // receiver coin 2
	]
	.to_vec();
	let sn_1: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(sender_1.2.sn.as_ref()).unwrap();
	let sn_2: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(sender_2.2.sn.as_ref()).unwrap();
	let mr: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&merkle_root).unwrap();
	inputs = [
		inputs[..].as_ref(),
		sn_1.as_ref(),
		sn_2.as_ref(),
		mr.as_ref(),
		mr.as_ref(),
	]
	.concat();
	let pvk = param::Groth16PVK::from(pk.vk.clone());
	assert!(verify_proof(&pvk, &proof, &inputs[..]).unwrap());
}

/// this is a local test on zero knowledge proof generation and verifications
#[test]
fn test_reclaim_zkp_local() {
	let hash_param = HashParam::deserialize(HASH_PARAM_BYTES.as_ref());
	let commit_param = CommitmentParam::deserialize(COMMIT_PARAM_BYTES.as_ref());

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
	let (receiver, receiver_pub_info, _receiver_priv_info) =
		make_coin(&commit_param, sk, 240, &mut rng);

	// list of commitment
	let mut list = vec![sender_1.cm_bytes.clone(), sender_2.cm_bytes.clone()];
	for _e in 1..24 {
		let mut cm_rand = [0u8; 32];
		rng.fill_bytes(&mut cm_rand);
		list.push(cm_rand);
	}

	let tree = param::LedgerMerkleTree::new(hash_param.clone(), &list).unwrap();
	let merkle_root = tree.root();

	let index_1 = list.iter().position(|x| *x == sender_1.cm_bytes).unwrap();
	let path_1 = tree.generate_proof(index_1, &sender_1.cm_bytes).unwrap();

	let index_2 = list.iter().position(|x| *x == sender_2.cm_bytes).unwrap();
	let path_2 = tree.generate_proof(index_2, &sender_2.cm_bytes).unwrap();

	// build the circuit
	let circuit = crypto::ReclaimCircuit {
		commit_param: commit_param.clone(),
		hash_param: hash_param.clone(),

		sender_coin_1: sender_1.clone(),
		sender_pub_info_1: sender_pub_info_1.clone(),
		sender_priv_info_1: sender_priv_info_1.clone(),
		sender_membership_1: path_1,
		root_1: merkle_root.clone(),

		sender_coin_2: sender_2.clone(),
		sender_pub_info_2: sender_pub_info_2.clone(),
		sender_priv_info_2: sender_priv_info_2.clone(),
		sender_membership_2: path_2,
		root_2: merkle_root,

		receiver_coin: receiver.clone(),
		receiver_k: receiver_pub_info.k,
		receiver_s: receiver_pub_info.s,
		receiver_value: 240,

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
	let sender_1 = make_coin(&commit_param, sk, 100, &mut rng);
	rng.fill_bytes(&mut sk);
	let sender_2 = make_coin(&commit_param, sk, 400, &mut rng);
	list.push(sender_1.0.cm_bytes);
	list.push(sender_2.0.cm_bytes);

	rng.fill_bytes(&mut sk);
	let receiver = make_coin(&commit_param, sk, 300, &mut rng);

	test_reclaim_helper(
		commit_param.clone(),
		hash_param.clone(),
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
	let sender_1 = make_coin(&commit_param, sk, 0, &mut rng);
	rng.fill_bytes(&mut sk);
	let sender_2 = make_coin(&commit_param, sk, 500, &mut rng);
	list.push(sender_1.0.cm_bytes);
	list.push(sender_2.0.cm_bytes);

	rng.fill_bytes(&mut sk);
	let receiver = make_coin(&commit_param, sk, 100, &mut rng);

	test_reclaim_helper(
		commit_param.clone(),
		hash_param.clone(),
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
	let sender_1 = make_coin(&commit_param, sk, 77, &mut rng);
	rng.fill_bytes(&mut sk);
	let sender_2 = make_coin(&commit_param, sk, 423, &mut rng);
	list.push(sender_1.0.cm_bytes);
	list.push(sender_2.0.cm_bytes);

	rng.fill_bytes(&mut sk);
	let receiver = make_coin(&commit_param, sk, 0, &mut rng);

	test_reclaim_helper(
		commit_param.clone(),
		hash_param.clone(),
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
	let sender_1 = make_coin(&commit_param, sk, 42, &mut rng);
	rng.fill_bytes(&mut sk);
	let sender_2 = make_coin(&commit_param, sk, 458, &mut rng);
	list.push(sender_1.0.cm_bytes);
	list.push(sender_2.0.cm_bytes);

	rng.fill_bytes(&mut sk);
	let receiver = make_coin(&commit_param, sk, 500, &mut rng);

	test_reclaim_helper(
		commit_param.clone(),
		hash_param.clone(),
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
	hash_param: HashParam,
	pk: &Groth16PK,
	sender_1: (MantaCoin, MantaCoinPubInfo, MantaCoinPrivInfo),
	sender_2: (MantaCoin, MantaCoinPubInfo, MantaCoinPrivInfo),
	receiver: (MantaCoin, MantaCoinPubInfo, MantaCoinPrivInfo),
	reclaim_value: u64,
	list: &[[u8; 32]],
) {
	let mut rng = ChaCha20Rng::from_seed([8u8; 32]);

	let tree = param::LedgerMerkleTree::new(hash_param.clone(), &list).unwrap();
	let merkle_root = tree.root();

	let index_1 = list.iter().position(|x| *x == sender_1.0.cm_bytes).unwrap();
	let path_1 = tree.generate_proof(index_1, &sender_1.0.cm_bytes).unwrap();

	let index_2 = list.iter().position(|x| *x == sender_2.0.cm_bytes).unwrap();
	let path_2 = tree.generate_proof(index_2, &sender_2.0.cm_bytes).unwrap();

	let circuit = crypto::ReclaimCircuit {
		commit_param: commit_param.clone(),
		hash_param,

		sender_coin_1: sender_1.0.clone(),
		sender_pub_info_1: sender_1.1.clone(),
		sender_priv_info_1: sender_1.2.clone(),
		sender_membership_1: path_1.clone(),
		root_1: merkle_root.clone(),

		sender_coin_2: sender_2.0.clone(),
		sender_pub_info_2: sender_2.1.clone(),
		sender_priv_info_2: sender_2.2.clone(),
		sender_membership_2: path_2.clone(),
		root_2: merkle_root,

		receiver_coin: receiver.0.clone(),
		receiver_k: receiver.1.k,
		receiver_s: receiver.1.s,
		receiver_value: receiver.2.value,

		reclaim_value,
	};

	let sanity_cs = ConstraintSystem::<Fq>::new_ref();
	circuit
		.clone()
		.generate_constraints(sanity_cs.clone())
		.unwrap();
	assert!(sanity_cs.is_satisfied().unwrap());

	let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();

	let k_old_1 = param::CommitmentOutput::deserialize(sender_1.1.k.as_ref()).unwrap();
	let k_old_2 = param::CommitmentOutput::deserialize(sender_2.1.k.as_ref()).unwrap();
	let cm_new = param::CommitmentOutput::deserialize(receiver.0.cm_bytes.as_ref()).unwrap();

	// format the input to the verification
	let mut inputs = [
		k_old_1.x, k_old_1.y, // sender coin 3
		k_old_2.x, k_old_2.y, // sender coin 4
		cm_new.x, cm_new.y, // receiver coin 1
	]
	.to_vec();
	let sn_1: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(sender_1.2.sn.as_ref()).unwrap();
	let sn_2: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(sender_2.2.sn.as_ref()).unwrap();
	let mr: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&merkle_root).unwrap();
	let reclaim_value_fq = Fq::from(reclaim_value);
	inputs = [
		inputs[..].as_ref(),
		sn_1.as_ref(),
		sn_2.as_ref(),
		mr.as_ref(),
		mr.as_ref(),
		&[reclaim_value_fq],
	]
	.concat();
	let pvk = param::Groth16PVK::from(pk.vk.clone());
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
