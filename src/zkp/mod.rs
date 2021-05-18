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

mod reclaim;
mod transfer;

pub use reclaim::ReclaimCircuit;
pub use transfer::TransferCircuit;

use crate::payload::*;
use ark_crypto_primitives::{
	commitment::pedersen::Randomness,
	prf::{blake2s::constraints::Blake2sGadget, PRFGadget},
	CommitmentGadget, PathVar,
};
use ark_ed_on_bls12_381::{EdwardsProjective, Fq, Fr};
use ark_ff::ToConstraintField;
use ark_groth16::verify_proof;
use ark_r1cs_std::{alloc::AllocVar, prelude::*};
use ark_relations::r1cs::ConstraintSystemRef;
use ark_serialize::CanonicalDeserialize;
use ark_std::vec::Vec;
use manta_crypto::*;
use pallet_manta_asset::*;

pub fn manta_verify_transfer_zkp(
	transfer_key_bytes: &VerificationKey,
	proof: &[u8; 192],
	sender_data_1: &SenderData,
	sender_data_2: &SenderData,
	receiver_data_1: &ReceiverData,
	receiver_data_2: &ReceiverData,
) -> bool {
	let buf: &[u8] = transfer_key_bytes.data;
	let vk = Groth16Vk::deserialize_unchecked(buf).unwrap();
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
	reclaim_key_bytes: &VerificationKey,
	value: u64,
	proof: &[u8; 192],
	sender_data_1: &SenderData,
	sender_data_2: &SenderData,
	receiver_data: &ReceiverData,
) -> bool {
	let buf: &[u8] = reclaim_key_bytes.data;
	let vk = Groth16Vk::deserialize_unchecked(buf).unwrap();
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

// =============================
// circuit for the following statements
// 1. k = com(pk||rho, r)
// 2. cm = com(v||k, s)
// for the sender, the cm is hidden and k is public
// =============================
pub(crate) fn sender_token_well_formed_circuit_helper(
	parameters_var: &CommitmentParamVar,
	asset: &MantaAsset,
	cs: ConstraintSystemRef<Fq>,
) {
	// =============================
	// statement 1: k = com(pk||rho, r)
	// =============================
	let input: Vec<u8> = [asset.pub_info.pk.as_ref(), asset.pub_info.rho.as_ref()].concat();
	let mut input_var = Vec::new();
	for byte in &input {
		input_var.push(UInt8::new_witness(cs.clone(), || Ok(*byte)).unwrap());
	}

	// opening
	let r = Fr::deserialize(asset.pub_info.r.as_ref()).unwrap();
	let r = Randomness::<EdwardsProjective>(r);
	let randomness_var = MantaCoinCommitmentOpenVar::new_witness(
		ark_relations::ns!(cs, "gadget_randomness"),
		|| Ok(&r),
	)
	.unwrap();

	// commitment
	let result_var =
		CommitmentSchemeVar::commit(&parameters_var, &input_var, &randomness_var).unwrap();

	// circuit to compare the committed value with supplied value
	let k = CommitmentOutput::deserialize(asset.pub_info.k.as_ref()).unwrap();
	let commitment_var2 = MantaCoinCommitmentOutputVar::new_input(
		ark_relations::ns!(cs, "gadget_commitment"),
		|| Ok(k),
	)
	.unwrap();
	result_var.enforce_equal(&commitment_var2).unwrap();

	// =============================
	// statement 2: cm = com(v||k, s)
	// =============================
	let input: Vec<u8> = [
		asset.priv_info.value.to_le_bytes().as_ref(),
		asset.pub_info.k.as_ref(),
	]
	.concat();
	let mut input_var = Vec::new();
	for byte in &input {
		input_var.push(UInt8::new_witness(cs.clone(), || Ok(*byte)).unwrap());
	}

	// opening
	let s = Randomness::<EdwardsProjective>(Fr::deserialize(asset.pub_info.s.as_ref()).unwrap());
	let randomness_var = MantaCoinCommitmentOpenVar::new_witness(
		ark_relations::ns!(cs, "gadget_randomness"),
		|| Ok(&s),
	)
	.unwrap();

	// commitment
	let result_var: MantaCoinCommitmentOutputVar =
		CommitmentSchemeVar::commit(&parameters_var, &input_var, &randomness_var).unwrap();

	// the other commitment
	let cm = CommitmentOutput::deserialize(asset.commitment.as_ref()).unwrap();
	// the commitment is from the sender, so it is hidden
	let commitment_var2 = MantaCoinCommitmentOutputVar::new_witness(
		ark_relations::ns!(cs, "gadget_commitment"),
		|| Ok(cm),
	)
	.unwrap();

	// circuit to compare the committed value with supplied value
	result_var.enforce_equal(&commitment_var2).unwrap();
}

// =============================
// circuit for the following statements
// 1. cm = com(v||k, s)
// for the receiver, the cm is public
// =============================
pub(crate) fn receiver_token_well_formed_circuit_helper(
	parameters_var: &CommitmentParamVar,
	receiver: &MantaAssetProcessedReceiver,
	cs: ConstraintSystemRef<Fq>,
) {
	// =============================
	// statement 1: cm = com(v||k, s)
	// =============================
	let input: Vec<u8> = [
		receiver.value.to_le_bytes().as_ref(),
		receiver.prepared_data.k.as_ref(),
	]
	.concat();
	let mut input_var = Vec::new();
	for byte in &input {
		input_var.push(UInt8::new_witness(cs.clone(), || Ok(*byte)).unwrap());
	}

	// opening
	let s = Randomness::<EdwardsProjective>(
		Fr::deserialize(receiver.prepared_data.s.as_ref()).unwrap(),
	);
	let randomness_var = MantaCoinCommitmentOpenVar::new_witness(
		ark_relations::ns!(cs, "gadget_randomness"),
		|| Ok(&s),
	)
	.unwrap();

	// commitment
	let result_var: MantaCoinCommitmentOutputVar =
		CommitmentSchemeVar::commit(&parameters_var, &input_var, &randomness_var).unwrap();

	// the other commitment
	let cm = CommitmentOutput::deserialize(receiver.commitment.as_ref()).unwrap();
	// the commitment is from the receiver, it is public
	let commitment_var2 = MantaCoinCommitmentOutputVar::new_input(
		ark_relations::ns!(cs, "gadget_commitment"),
		|| Ok(cm),
	)
	.unwrap();

	// circuit to compare the committed value with supplied value
	result_var.enforce_equal(&commitment_var2).unwrap();
}

/// A helper function to generate the prf circuit
///     sender.pk = PRF(sender_sk, [0u8;32])
///     sender.sn = PRF(sender_sk, rho)
/// the output pk is hidden, while sn can be public
pub(crate) fn prf_circuit_helper(
	is_output_hidden: bool,
	seed: &[u8; 32],
	input: &[u8; 32],
	output: &[u8; 32],
	cs: ConstraintSystemRef<Fq>,
) {
	// step 1. Allocate seed
	let seed_var = Blake2sGadget::new_seed(cs.clone(), &seed);

	// step 2. Allocate inputs
	let input_var = UInt8::new_witness_vec(ark_relations::ns!(cs, "declare_input"), input).unwrap();

	// step 3. Allocate evaluated output
	let output_var = Blake2sGadget::evaluate(&seed_var, &input_var).unwrap();

	// step 4. Actual output
	let actual_out_var = if is_output_hidden {
		<Blake2sGadget as PRFGadget<_, Fq>>::OutputVar::new_witness(
			ark_relations::ns!(cs, "declare_output"),
			|| Ok(output),
		)
		.unwrap()
	} else {
		<Blake2sGadget as PRFGadget<_, Fq>>::OutputVar::new_input(
			ark_relations::ns!(cs, "declare_output"),
			|| Ok(output),
		)
		.unwrap()
	};

	// step 5. compare the outputs
	output_var.enforce_equal(&actual_out_var).unwrap();
}

pub(crate) fn merkle_membership_circuit_proof(
	cm: &[u8; 32],
	path: &AccountMembership,
	param_var: HashParamVar,
	root: HashOutput,
	cs: ConstraintSystemRef<Fq>,
) {
	let root_var =
		HashOutputVar::new_input(ark_relations::ns!(cs, "new_digest"), || Ok(root)).unwrap();

	// Allocate Merkle Tree Path
	let membership_var =
		PathVar::<_, HashVar, _>::new_witness(ark_relations::ns!(cs, "new_witness"), || Ok(path))
			.unwrap();

	// Allocate Leaf
	let leaf_var = UInt8::new_witness_vec(ark_relations::ns!(cs, "commitment"), cm).unwrap();
	let leaf_var: &[_] = leaf_var.as_slice();

	// check membership
	membership_var
		.check_membership(&param_var, &root_var, &leaf_var)
		.unwrap()
		.enforce_equal(&Boolean::TRUE)
		.unwrap();
}
