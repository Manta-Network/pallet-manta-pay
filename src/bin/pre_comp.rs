use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{CommitmentScheme as ArkCommitmentScheme, FixedLengthCRH};
use ark_ed_on_bls12_381::Fq;
use ark_groth16::{create_random_proof, generate_random_parameters};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use data_encoding::BASE64;
use pallet_manta_dap::*;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{fs::File, io::prelude::*};
use x25519_dalek::{PublicKey, StaticSecret};

fn main() {
	println!("Hello, Manta!");

	let hash_param_seed = [1u8; 32];
	let commit_param_seed = [2u8; 32];

	// let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
	// let hash_param = Hash::setup(&mut rng).unwrap();

	// let mut hash_param_bytes = vec![];
	// hash_param.serialize(&mut hash_param_bytes);
	// println!("hash param len: {}", hash_param_bytes.len());
	// // println!("hash_param_bytes: {:?}", hash_param_bytes);

	// let mut rng = ChaCha20Rng::from_seed(commit_param_seed);
	// let commit_param = CommitmentScheme::setup(&mut rng).unwrap();

	// let mut commit_param_bytes = vec![];
	// commit_param.serialize(&mut commit_param_bytes);
	// println!("commit param len: {}", commit_param_bytes.len());
	// // println!("commit_param_bytes: {:?}", commit_param_bytes);

	// let (coin1, pub_info1, priv_info1) = make_coin(&commit_param, [0u8; 32], 10, &mut rng);

	// coin_print_json(&coin1, &pub_info1, &priv_info1);

	// let (coin2, pub_info2, priv_info2) = make_coin(&commit_param, [1u8; 32], 100, &mut rng);

	// coin_print_json(&coin2, &pub_info2, &priv_info2);

	// let (coin3, pub_info3, priv_info3) = make_coin(&commit_param, [2u8; 32], 10, &mut rng);

	// coin_print_json(&coin3, &pub_info3, &priv_info3);

	// coin_print_plain(&coin1, &pub_info1, &priv_info1);
	// coin_print_plain(&coin2, &pub_info2, &priv_info2);
	// coin_print_plain(&coin3, &pub_info3, &priv_info3);

	let mut transfer_pk_bytes = manta_transfer_zkp_key_gen(&hash_param_seed, &commit_param_seed);
	let mut file = File::create("transfer_pk.bin").unwrap();
	file.write_all(transfer_pk_bytes.as_mut()).unwrap();
	println!("{}", transfer_pk_bytes.len());

	let mut reclaim_pk_bytes = manta_reclaim_zkp_key_gen(&hash_param_seed, &commit_param_seed);
	let mut file = File::create("reclaim_pk.bin").unwrap();
	file.write_all(reclaim_pk_bytes.as_mut()).unwrap();
	println!("{}", reclaim_pk_bytes.len());

	// // ===========================
	// // testing DH encryption
	// // ===========================

	// let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
	// let receiver_sk = StaticSecret::new(&mut rng);
	// let receiver_pk = PublicKey::from(&receiver_sk);
	// let receiver_pk_bytes = receiver_pk.to_bytes();
	// let receiver_sk_bytes = receiver_sk.to_bytes();
	// let value = 10;
	// let (sender_pk_bytes, cipher) = manta_dh_enc(&receiver_pk_bytes, value, &mut rng);
	// println!("enc success");
	// let rec_value = manta_dh_dec(&cipher, &sender_pk_bytes, &receiver_sk_bytes);
	// assert_eq!(value, rec_value);

	// println!("\"sender_pk\": \"{}\",", BASE64.encode(&sender_pk_bytes));
	// println!(
	// 	"\"receiver_pk\": \"{}\",",
	// 	BASE64.encode(&receiver_pk_bytes)
	// );
	// println!(
	// 	"\"receiver_sk\": \"{}\",",
	// 	BASE64.encode(&receiver_sk_bytes)
	// );
	// println!("\"ciphertext\": \"{}\",", BASE64.encode(&cipher));

	// // ===========================
	// // testing transfer circuit
	// // ===========================
	// let transfer_pk = Groth16PK::deserialize_uncompressed(transfer_pk_bytes.as_ref()).unwrap();
	// let transfer_vk = transfer_pk.vk.clone();
	// let mut vk_buf: Vec<u8> = vec![];
	// transfer_vk.serialize(&mut vk_buf).unwrap();
	// println!("pk_uncompressed len {}", transfer_pk_bytes.len());
	// println!("vk: {:?}", vk_buf);

	// let circuit = TransferCircuit {
	// 	commit_param: commit_param.clone(),
	// 	hash_param: hash_param.clone(),
	// 	sender_coin: coin1.clone(),
	// 	sender_pub_info: pub_info1.clone(),
	// 	sender_priv_info: priv_info1.clone(),
	// 	receiver_coin: coin3.clone(),
	// 	receiver_pub_info: pub_info3.clone(),
	// 	list: vec![coin1.cm_bytes],
	// };

	// let sanity_cs = ConstraintSystem::<Fq>::new_ref();
	// circuit
	// 	.clone()
	// 	.generate_constraints(sanity_cs.clone())
	// 	.unwrap();
	// assert!(sanity_cs.is_satisfied().unwrap());

	// let proof = create_random_proof(circuit, &transfer_pk, &mut rng).unwrap();
	// let mut proof_bytes = [0u8; 192];
	// proof.serialize(proof_bytes.as_mut()).unwrap();

	// assert_eq!(
	// 	BASE64.decode(BASE64.encode(&proof_bytes).as_ref()).unwrap(),
	// 	proof_bytes
	// );

	// let tree = LedgerMerkleTree::new(hash_param.clone(), &[coin1.cm_bytes]).unwrap();
	// let merkle_root = tree.root();
	// let mut merkle_root_bytes = [0u8; 32];
	// merkle_root.serialize(merkle_root_bytes.as_mut()).unwrap();

	// let sender_data = SenderData {
	// 	k: pub_info1.k,
	// 	sn: priv_info1.sn,
	// };
	// let receiver_data = ReceiverData {
	// 	k: pub_info3.k,
	// 	cm: coin3.cm_bytes,
	// 	cipher,
	// };

	// assert!(manta_verify_transfer_zkp(
	// 	vk_buf,
	// 	proof_bytes,
	// 	&sender_data,
	// 	&receiver_data,
	// 	merkle_root_bytes
	// ));

	// let sender_data = [pub_info1.k, priv_info1.sn].concat();
	// let receiver_data = [
	// 	pub_info3.k.as_ref(),
	// 	coin3.cm_bytes.as_ref(),
	// 	[0u8; 16].as_ref(),
	// ]
	// .concat();

	// println!(
	// 	"\"merkle_roots\": \"{}\",",
	// 	BASE64.encode(&merkle_root_bytes)
	// );
	// println!("\"sn_old\": \"{}\",", BASE64.encode(&priv_info1.sn));
	// println!("\"k_old\": \"{}\",", BASE64.encode(&pub_info1.k));
	// println!("\"k_new\": \"{}\",", BASE64.encode(&pub_info3.k));
	// println!("\"cm_new\": \"{}\",", BASE64.encode(&coin3.cm_bytes));
	// println!("\"enc_amount\": \"{}\",", BASE64.encode(&cipher));
	// println!("\"value\": 10,");
	// println!("\"proof encoded\": \"{}\",", BASE64.encode(&proof_bytes));
	// println!("\"sender_data\": \"{}\",", BASE64.encode(&sender_data));
	// println!("\"receiver_data\": \"{}\",", BASE64.encode(&receiver_data));

	// println!("===========");
	// println!("\"merkle_roots\": \"{:02x?}\",", merkle_root_bytes);
	// println!("\"sn_old\": \"{:02x?}\",", priv_info1.sn);
	// println!("\"k_old\": \"{:02x?}\",", pub_info1.k);
	// println!("\"k_new\": \"{:02x?}\",", pub_info3.k);
	// println!("\"cm_new\": \"{:02x?}\",", coin3.cm_bytes);
	// println!("\"enc_amount\": \"{:02x?}\",", cipher);
	// println!("\"value\": 10,");
	// println!("\"proof encoded\": \"{:02x?}\",", proof_bytes);
	// println!("\"sender_data\": \"{:02x?}\",", sender_data);
	// println!("\"receiver_data\": \"{:02x?}\",", receiver_data);
	// println!("===========");

	// // ===========================
	// // testing reclaim circuit
	// // ===========================

	// let reclaim_pk = Groth16PK::deserialize_uncompressed(reclaim_pk_bytes.as_ref()).unwrap();
	// let reclaim_vk = reclaim_pk.vk.clone();
	// let mut vk_buf: Vec<u8> = vec![];
	// reclaim_vk.serialize(&mut vk_buf).unwrap();
	// println!("pk_uncompressed len {}", reclaim_pk_bytes.len());
	// println!("vk: {:?}", vk_buf);

	// let circuit2 = ReclaimCircuit {
	// 	commit_param,
	// 	hash_param: hash_param.clone(),
	// 	sender_coin: coin3.clone(),
	// 	sender_pub_info: pub_info3.clone(),
	// 	sender_priv_info: priv_info3.clone(),
	// 	value: 10,
	// 	list: vec![coin1.cm_bytes, coin3.cm_bytes],
	// };

	// let sanity_cs = ConstraintSystem::<Fq>::new_ref();
	// circuit2
	// 	.clone()
	// 	.generate_constraints(sanity_cs.clone())
	// 	.unwrap();
	// assert!(sanity_cs.is_satisfied().unwrap());

	// let proof = create_random_proof(circuit2, &reclaim_pk, &mut rng).unwrap();
	// let mut proof_bytes = [0u8; 192];
	// proof.serialize(proof_bytes.as_mut()).unwrap();

	// assert_eq!(
	// 	BASE64.decode(BASE64.encode(&proof_bytes).as_ref()).unwrap(),
	// 	proof_bytes
	// );

	// let tree = LedgerMerkleTree::new(hash_param, &[coin1.cm_bytes, coin3.cm_bytes]).unwrap();
	// let merkle_root = tree.root();
	// let mut merkle_root_bytes = [0u8; 32];
	// merkle_root.serialize(merkle_root_bytes.as_mut()).unwrap();

	// let sender_data = SenderData {
	// 	k: pub_info3.k,
	// 	sn: priv_info3.sn,
	// };
	// assert!(manta_verify_reclaim_zkp(
	// 	vk_buf,
	// 	10,
	// 	proof_bytes,
	// 	&sender_data,
	// 	merkle_root_bytes
	// ));

	// let sender_data = [pub_info3.k, priv_info3.sn].concat();

	// println!(
	// 	"\"merkle_roots\": \"{}\",",
	// 	BASE64.encode(&merkle_root_bytes)
	// );
	// println!("\"sn_old\": \"{}\",", BASE64.encode(&priv_info3.sn));
	// println!("\"k_old\": \"{}\",", BASE64.encode(&pub_info3.k));
	// println!("\"value\": 10,");
	// println!("\"proof encoded\": \"{}\",", BASE64.encode(&proof_bytes));
	// println!("\"sender_data\": \"{}\",", BASE64.encode(&sender_data));

	// println!("===========");
	// println!("\"merkle_roots\": \"{:02x?}\",", merkle_root_bytes);
	// println!("\"sn_old\": \"{:02x?}\",", priv_info3.sn);
	// println!("\"k_old\": \"{:02x?}\",", pub_info3.k);
	// println!("\"value\": 10,");
	// println!("\"proof encoded\": \"{:02x?}\",", proof_bytes);
	// println!("\"sender_data\": \"{:02x?}\",", sender_data);
	// println!("===========");
}

fn coin_print_json(coin: &MantaCoin, pub_info: &MantaCoinPubInfo, priv_info: &MantaCoinPrivInfo) {
	println!("\n==================");
	println!("\"cm\": \"{}\",", BASE64.encode(&coin.cm_bytes));
	println!("\"value\": {},", priv_info.value);
	println!("\"pk\": \"{}\",", BASE64.encode(&pub_info.pk));
	println!("\"rho\": \"{}\",", BASE64.encode(&pub_info.rho));
	println!("\"s\": \"{}\",", BASE64.encode(&pub_info.s));
	println!("\"r\": \"{}\",", BASE64.encode(&pub_info.r));
	println!("\"k\": \"{}\",", BASE64.encode(&pub_info.k));
	println!("\"sk\": \"{}\",", BASE64.encode(&priv_info.sk));
	println!("\"sn\": \"{}\",", BASE64.encode(&priv_info.sn));

	let mint_data = [coin.cm_bytes, pub_info.k, pub_info.s].concat();
	println!("\"mint_data\": \"{}\",", BASE64.encode(&mint_data));

	let sender_data = [pub_info.k, priv_info.sn].concat();
	println!("\"sender_data\": \"{}\",", BASE64.encode(&sender_data));

	let receiver_data = [
		pub_info.k.as_ref(),
		coin.cm_bytes.as_ref(),
		[0u8; 16].as_ref(),
	]
	.concat();
	println!("\"reciver_data\": \"{}\",", BASE64.encode(&receiver_data));

	println!("==================\n");
}

fn coin_print_plain(coin: &MantaCoin, pub_info: &MantaCoinPubInfo, priv_info: &MantaCoinPrivInfo) {
	println!("\n==================");
	println!("\"cm\": \"{:02x?}\",", coin.cm_bytes);
	println!("\"value\": {},", priv_info.value);
	println!("\"pk\": \"{:02x?}\",", pub_info.pk);
	println!("\"rho\": \"{:02x?}\",", pub_info.rho);
	println!("\"s\": \"{:02x?}\",", pub_info.s);
	println!("\"r\": \"{:02x?}\",", pub_info.r);
	println!("\"k\": \"{:02x?}\",", pub_info.k);
	println!("\"sk\": \"{:02x?}\",", priv_info.sk);
	println!("\"sn\": \"{:02x?}\",", priv_info.sn);

	let mint_data = [coin.cm_bytes, pub_info.k, pub_info.s].concat();
	println!("\"mint_data\": \"{:02x?}\",", mint_data);

	let sender_data = [pub_info.k, priv_info.sn].concat();
	println!("\"sender_data\": \"{:02x?}\",", sender_data);

	let receiver_data = [
		pub_info.k.as_ref(),
		coin.cm_bytes.as_ref(),
		[0u8; 16].as_ref(),
	]
	.concat();
	println!("\"receiver_data\": \"{:02x?}\",", receiver_data);
	println!("==================\n");
}

#[allow(dead_code)]
fn manta_transfer_zkp_key_gen(hash_param_seed: &[u8; 32], commit_param_seed: &[u8; 32]) -> Vec<u8> {
	// rebuild the parameters from the inputs
	let mut rng = ChaCha20Rng::from_seed(*commit_param_seed);
	let commit_param = CommitmentScheme::setup(&mut rng).unwrap();

	let mut rng = ChaCha20Rng::from_seed(*hash_param_seed);
	let hash_param = Hash::setup(&mut rng).unwrap();

	let zkp_seed: [u8; 32] = *b"this is a seed for manta zk test";
	println!("zkp_seed {:02x?}", zkp_seed);

	let mut rng = ChaCha20Rng::from_seed(zkp_seed);
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

		sender_coin_2: sender_2.0,
		sender_pub_info_2: sender_2.1,
		sender_priv_info_2: sender_2.2,

		// receiver
		receiver_coin_1: receiver_1.0,
		receiver_pub_info_1: receiver_1.1,
		receiver_value_1: receiver_1.2.value,

		receiver_coin_2: receiver_2.0,
		receiver_pub_info_2: receiver_2.1,
		receiver_value_2: receiver_2.2.value,

		// ledger
		list: ledger,
	};

	let sanity_cs = ConstraintSystem::<Fq>::new_ref();
	transfer_circuit
		.clone()
		.generate_constraints(sanity_cs.clone())
		.unwrap();
	assert!(sanity_cs.is_satisfied().unwrap());

	// transfer pk_bytes
	let mut rng = ChaCha20Rng::from_seed(zkp_seed);
	let pk = generate_random_parameters::<Bls12_381, _, _>(transfer_circuit, &mut rng).unwrap();
	let mut transfer_pk_bytes: Vec<u8> = Vec::new();

	pk.serialize_uncompressed(&mut transfer_pk_bytes).unwrap();
	transfer_pk_bytes
}

fn manta_reclaim_zkp_key_gen(hash_param_seed: &[u8; 32], commit_param_seed: &[u8; 32]) -> Vec<u8> {
	// rebuild the parameters from the inputs
	let mut rng = ChaCha20Rng::from_seed(*commit_param_seed);
	let commit_param = CommitmentScheme::setup(&mut rng).unwrap();

	let mut rng = ChaCha20Rng::from_seed(*hash_param_seed);
	let hash_param = Hash::setup(&mut rng).unwrap();

	let zkp_seed: [u8; 32] = *b"this is a seed for manta zk test";
	let mut rng = ChaCha20Rng::from_seed(zkp_seed);
	let mut coins = Vec::new();
	let mut pub_infos = Vec::new();
	let mut priv_infos = Vec::new();
	let mut ledger = Vec::new();

	for e in 0..128 {
		let mut sk = [0u8; 32];
		rng.fill_bytes(&mut sk);

		let (coin, pub_info, priv_info) = make_coin(&commit_param, sk, e + 100, &mut rng);

		ledger.push(coin.cm_bytes);
		coins.push(coin);
		pub_infos.push(pub_info);
		priv_infos.push(priv_info);
	}

	// sender
	let sender = coins[0].clone();
	let sender_pub_info = pub_infos[0].clone();
	let sender_priv_info = priv_infos[0].clone();

	// reclaim circuit
	let reclaim_circuit = ReclaimCircuit {
		commit_param,
		hash_param,
		sender_coin: sender,
		sender_pub_info,
		sender_priv_info: sender_priv_info.clone(),
		value: sender_priv_info.value,
		list: ledger,
	};

	let sanity_cs = ConstraintSystem::<Fq>::new_ref();
	reclaim_circuit
		.clone()
		.generate_constraints(sanity_cs.clone())
		.unwrap();
	assert!(sanity_cs.is_satisfied().unwrap());

	// transfer pk_bytes
	let mut rng = ChaCha20Rng::from_seed(zkp_seed);
	let pk = generate_random_parameters::<Bls12_381, _, _>(reclaim_circuit, &mut rng).unwrap();
	let mut reclaim_pk_bytes: Vec<u8> = Vec::new();
	pk.serialize_uncompressed(&mut reclaim_pk_bytes).unwrap();
	reclaim_pk_bytes
}
// fn main() {}
