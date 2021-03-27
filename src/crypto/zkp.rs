use crate::{coin::*, param::*};
use ark_ed_on_bls12_381::Fq;
use ark_ff::ToConstraintField;
use ark_groth16::verify_proof;
use ark_serialize::CanonicalDeserialize;
use ark_std::vec::Vec;

pub fn manta_verify_transfer_zkp(
	transfer_key_bytes: Vec<u8>,
	proof: [u8; 192],
	sender_data_1: &SenderData,
	sender_data_2: &SenderData,
	receiver_data_1: &ReceiverData,
	receiver_data_2: &ReceiverData,
	merkle_root: [u8; 32],
) -> bool {
	let vk = Groth16VK::deserialize(transfer_key_bytes.as_ref()).unwrap();
	let pvk = Groth16PVK::from(vk);
	let proof = Groth16Proof::deserialize(proof.as_ref()).unwrap();
	let k_old_1 = CommitmentOutput::deserialize(sender_data_1.k.as_ref()).unwrap();
	let k_old_2 = CommitmentOutput::deserialize(sender_data_2.k.as_ref()).unwrap();
	let k_new_1 = CommitmentOutput::deserialize(receiver_data_1.k.as_ref()).unwrap();
	let k_new_2 = CommitmentOutput::deserialize(receiver_data_2.k.as_ref()).unwrap();
	let cm_new_1 = CommitmentOutput::deserialize(receiver_data_1.cm.as_ref()).unwrap();
	let cm_new_2 = CommitmentOutput::deserialize(receiver_data_2.cm.as_ref()).unwrap();
	let merkle_root = HashOutput::deserialize(merkle_root.as_ref()).unwrap();

	let mut inputs = [
		k_old_1.x, k_old_1.y, // sender coin 1
		k_old_2.x, k_old_2.y, // sender coin 2
		k_new_1.x, k_new_1.y, cm_new_1.x, cm_new_1.y, // receiver coin 1
		k_new_2.x, k_new_2.y, cm_new_2.x, cm_new_2.y, // receiver coin 2
	]
	.to_vec();
	let sn_1: Vec<Fq> =
		ToConstraintField::<Fq>::to_field_elements(sender_data_1.sn.as_ref()).unwrap();
	let sn_2: Vec<Fq> =
		ToConstraintField::<Fq>::to_field_elements(sender_data_2.sn.as_ref()).unwrap();

	let mr: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&merkle_root).unwrap();
	inputs = [
		inputs[..].as_ref(),
		sn_1.as_ref(),
		sn_2.as_ref(),
		mr.as_ref(),
	]
	.concat();

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
