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
) -> bool {
	let buf: &[u8] = transfer_key_bytes.as_ref();
	let vk = Groth16Vk::deserialize(buf).unwrap();
	let pvk = Groth16Pvk::from(vk);
	let proof = Groth16Proof::deserialize(proof.as_ref()).unwrap();
	let k_old_1 = CommitmentOutput::deserialize(sender_data_1.k.as_ref()).unwrap();
	let k_old_2 = CommitmentOutput::deserialize(sender_data_2.k.as_ref()).unwrap();
	let cm_new_1 = CommitmentOutput::deserialize(receiver_data_1.cm.as_ref()).unwrap();
	let cm_new_2 = CommitmentOutput::deserialize(receiver_data_2.cm.as_ref()).unwrap();
	let merkle_root_1 = HashOutput::deserialize(sender_data_1.root.as_ref()).unwrap();
	let merkle_root_2 = HashOutput::deserialize(sender_data_2.root.as_ref()).unwrap();

	let mut inputs = [
		k_old_1.x, k_old_1.y, // sender coin 1
		k_old_2.x, k_old_2.y, // sender coin 2
		cm_new_1.x, cm_new_1.y, // receiver coin 1
		cm_new_2.x, cm_new_2.y, // receiver coin 2
	]
	.to_vec();
	let sn_1: Vec<Fq> =
		ToConstraintField::<Fq>::to_field_elements(sender_data_1.sn.as_ref()).unwrap();
	let sn_2: Vec<Fq> =
		ToConstraintField::<Fq>::to_field_elements(sender_data_2.sn.as_ref()).unwrap();

	let mr_1: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&merkle_root_1).unwrap();
	let mr_2: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&merkle_root_2).unwrap();
	inputs = [
		inputs[..].as_ref(),
		sn_1.as_ref(),
		sn_2.as_ref(),
		mr_1.as_ref(),
		mr_2.as_ref(),
	]
	.concat();

	verify_proof(&pvk, &proof, &inputs[..]).unwrap()
}

pub fn manta_verify_reclaim_zkp(
	reclaim_key_bytes: Vec<u8>,
	value: u64,
	proof: [u8; 192],
	sender_data_1: &SenderData,
	sender_data_2: &SenderData,
	receiver_data: &ReceiverData,
) -> bool {
	let buf: &[u8] = reclaim_key_bytes.as_ref();
	let vk = Groth16Vk::deserialize(buf).unwrap();
	let pvk = Groth16Pvk::from(vk);
	let proof = Groth16Proof::deserialize(proof.as_ref()).unwrap();
	let k_old_1 = CommitmentOutput::deserialize(sender_data_1.k.as_ref()).unwrap();
	let k_old_2 = CommitmentOutput::deserialize(sender_data_2.k.as_ref()).unwrap();
	let cm_new = CommitmentOutput::deserialize(receiver_data.cm.as_ref()).unwrap();
	let merkle_root_1 = HashOutput::deserialize(sender_data_1.root.as_ref()).unwrap();
	let merkle_root_2 = HashOutput::deserialize(sender_data_2.root.as_ref()).unwrap();

	let mut inputs = [
		k_old_1.x, k_old_1.y, // sender coin 1
		k_old_2.x, k_old_2.y, // sender coin 2
		cm_new.x, cm_new.y, // receiver coin
	]
	.to_vec();
	let sn_1: Vec<Fq> =
		ToConstraintField::<Fq>::to_field_elements(sender_data_1.sn.as_ref()).unwrap();
	let sn_2: Vec<Fq> =
		ToConstraintField::<Fq>::to_field_elements(sender_data_2.sn.as_ref()).unwrap();

	let mr_1: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&merkle_root_1).unwrap();
	let mr_2: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&merkle_root_2).unwrap();
	let value_fq = Fq::from(value);
	inputs = [
		inputs[..].as_ref(),
		sn_1.as_ref(),
		sn_2.as_ref(),
		mr_1.as_ref(),
		mr_2.as_ref(),
		[value_fq].as_ref(),
	]
	.concat();

	verify_proof(&pvk, &proof, &inputs[..]).unwrap()
}
