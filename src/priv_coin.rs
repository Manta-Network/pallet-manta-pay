use crate::param::*;
use ark_crypto_primitives::{commitment::pedersen::Randomness, CommitmentScheme};
use ark_ed_on_bls12_381::{Fq, Fr};
use ark_ff::ToConstraintField;
use ark_groth16::verify_proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;

#[allow(dead_code)]
pub fn comm_open(
	com_param: &MantaCoinCommitmentParam,
	r: &[u8; 32],
	payload: &[u8],
	cm: &[u8; 32],
) -> bool {
	let open = Randomness(Fr::deserialize(r.as_ref()).unwrap());
	let cm = MantaCoinCommitmentOutput::deserialize(cm.as_ref()).unwrap();
	MantaCoinCommitmentScheme::commit(com_param, payload, &open).unwrap() == cm
}

#[allow(dead_code)]
pub fn merkle_root(hash_param: HashParam, payload: &[[u8; 32]]) -> [u8; 32] {
	let tree = LedgerMerkleTree::new(hash_param, payload).unwrap();
	let root = tree.root();

	let mut bytes = [0u8; 32];
	root.serialize(bytes.as_mut()).unwrap();
	bytes
}

pub fn manta_verify_transfer_zkp(
	transfer_key_bytes: Vec<u8>,
	proof: [u8; 192],
	sender_data: &super::manta_token::SenderData,
	receiver_data: &super::manta_token::ReceiverData,
	merkle_root: [u8; 32],
) -> bool {
	let vk = Groth16VK::deserialize(transfer_key_bytes.as_ref()).unwrap();
	let pvk = Groth16PVK::from(vk);
	let proof = Groth16Proof::deserialize(proof.as_ref()).unwrap();
	let k_old = MantaCoinCommitmentOutput::deserialize(sender_data.k.as_ref()).unwrap();
	let k_new = MantaCoinCommitmentOutput::deserialize(receiver_data.k.as_ref()).unwrap();
	let cm_new = MantaCoinCommitmentOutput::deserialize(receiver_data.cm.as_ref()).unwrap();
	let merkle_root = HashOutput::deserialize(merkle_root.as_ref()).unwrap();

	let mut inputs = [k_old.x, k_old.y, k_new.x, k_new.y, cm_new.x, cm_new.y].to_vec();
	let sn: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(sender_data.sn.as_ref()).unwrap();
	let mr: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&merkle_root).unwrap();
	inputs = [inputs[..].as_ref(), sn.as_ref(), mr.as_ref()].concat();

	verify_proof(&pvk, &proof, &inputs[..]).unwrap()
}

pub fn manta_verify_reclaim_zkp(
	reclaim_key_bytes: Vec<u8>,
	value: u64,
	proof: [u8; 192],
	sender_data: &super::manta_token::SenderData,
	merkle_root: [u8; 32],
) -> bool {
	let vk = Groth16VK::deserialize(reclaim_key_bytes.as_ref()).unwrap();
	let pvk = Groth16PVK::from(vk);
	let proof = Groth16Proof::deserialize(proof.as_ref()).unwrap();
	let k_old = MantaCoinCommitmentOutput::deserialize(sender_data.k.as_ref()).unwrap();
	let merkle_root = HashOutput::deserialize(merkle_root.as_ref()).unwrap();

	let mut inputs = [k_old.x, k_old.y].to_vec();
	let sn: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(sender_data.sn.as_ref()).unwrap();
	let mr: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&merkle_root).unwrap();
	let value_fq = Fq::from(value);
	inputs = [
		inputs[..].as_ref(),
		sn.as_ref(),
		mr.as_ref(),
		[value_fq].as_ref(),
	]
	.concat();

	verify_proof(&pvk, &proof, &inputs[..]).unwrap()
}
