use crate::{coin::*, param::*};
use ark_ed_on_bls12_381::Fq;
use ark_ff::ToConstraintField;
use ark_groth16::verify_proof;
use ark_serialize::CanonicalDeserialize;
use ark_std::vec::Vec;

pub fn manta_verify_transfer_zkp(
	transfer_key_bytes: Vec<u8>,
	proof: [u8; 192],
	sender_data: &SenderData,
	receiver_data: &ReceiverData,
	merkle_root: [u8; 32],
) -> bool {
	let vk = Groth16VK::deserialize(transfer_key_bytes.as_ref()).unwrap();
	let pvk = Groth16PVK::from(vk);
	let proof = Groth16Proof::deserialize(proof.as_ref()).unwrap();
	let k_old = CommitmentOutput::deserialize(sender_data.k.as_ref()).unwrap();
	let k_new = CommitmentOutput::deserialize(receiver_data.k.as_ref()).unwrap();
	let cm_new = CommitmentOutput::deserialize(receiver_data.cm.as_ref()).unwrap();
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
	sender_data: &SenderData,
	merkle_root: [u8; 32],
) -> bool {
	let vk = Groth16VK::deserialize(reclaim_key_bytes.as_ref()).unwrap();
	let pvk = Groth16PVK::from(vk);
	let proof = Groth16Proof::deserialize(proof.as_ref()).unwrap();
	let k_old = CommitmentOutput::deserialize(sender_data.k.as_ref()).unwrap();
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
