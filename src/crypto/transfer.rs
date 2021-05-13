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
use ark_crypto_primitives::{
	commitment::pedersen::Randomness,
	prf::{blake2s::constraints::Blake2sGadget, PRFGadget},
	CommitmentGadget, PathVar,
};
use ark_ed_on_bls12_381::{constraints::FqVar, EdwardsProjective, Fq, Fr};
use ark_r1cs_std::{alloc::AllocVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalDeserialize;
use ark_std::vec::Vec;

// =============================
/// ZK circuit for the __transfer__ statements.
/// # <weight>
/// 1. both sender's coins are well-formed:
///  * `k = com(pk||rho, r)`
///  * `cm = com(v||k, s)`
/// where k is public.
/// 2. both receiver's coins are well-formed
///  * `cm = com(v||k, s)`
/// where k and cm are both public.
/// 3. address and the secret key derives public key:
///  `sender.pk = PRF(sender_sk, [0u8;32])`
/// 4. sender's commitment is in CMList.
///  NOTE: we de not need to prove that sender's sn is not in VNList
///        this can be done in the public.
/// 5. sender's and receiver's combined values are the same.
/// # </weight>
// =============================
#[derive(Clone)]
pub struct TransferCircuit {
	// param
	pub commit_param: CommitmentParam,
	pub hash_param: HashParam,

	// sender
	pub sender_coin_1: MantaCoin,
	pub sender_pub_info_1: MantaCoinPubInfo,
	pub sender_priv_info_1: MantaCoinPrivInfo,
	pub sender_membership_1: AccountMembership,
	pub root_1: LedgerMerkleTreeRoot,

	pub sender_coin_2: MantaCoin,
	pub sender_pub_info_2: MantaCoinPubInfo,
	pub sender_priv_info_2: MantaCoinPrivInfo,
	pub sender_membership_2: AccountMembership,
	pub root_2: LedgerMerkleTreeRoot,

	// receiver
	pub receiver_coin_1: MantaCoin,
	pub receiver_k_1: [u8; 32],
	pub receiver_s_1: [u8; 32],
	pub receiver_value_1: u64,

	pub receiver_coin_2: MantaCoin,
	pub receiver_k_2: [u8; 32],
	pub receiver_s_2: [u8; 32],
	pub receiver_value_2: u64,
}

impl ConstraintSynthesizer<Fq> for TransferCircuit {
	/// Input a circuit, build the corresponding constraint system, and
	/// add it to `cs`.
	fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
		// 1. both sender's and receiver's coins are well-formed
		//  k = com(pk||rho, r)
		//  cm = com(v||k, s)

		// parameters
		let parameters_var =
			CommitmentParamVar::new_input(ark_relations::ns!(cs, "gadget_parameters"), || {
				Ok(&self.commit_param)
			})
			.unwrap();

		sender_token_well_formed_circuit_helper(
			&parameters_var,
			&self.sender_coin_1,
			&self.sender_pub_info_1,
			self.sender_priv_info_1.value,
			cs.clone(),
		);

		sender_token_well_formed_circuit_helper(
			&parameters_var,
			&self.sender_coin_2,
			&self.sender_pub_info_2,
			self.sender_priv_info_2.value,
			cs.clone(),
		);

		receiver_token_well_formed_circuit_helper(
			&parameters_var,
			&self.receiver_coin_1,
			&self.receiver_k_1,
			&self.receiver_s_1,
			self.receiver_value_1,
			cs.clone(),
		);

		receiver_token_well_formed_circuit_helper(
			&parameters_var,
			&self.receiver_coin_2,
			&self.receiver_k_2,
			&self.receiver_s_2,
			self.receiver_value_2,
			cs.clone(),
		);

		// 2. address and the secret key derives public key
		//  sender.pk = PRF(sender_sk, [0u8;32])
		//  sender.sn = PRF(sender_sk, rho)
		prf_circuit_helper(
			true,
			&self.sender_priv_info_1.sk,
			&[0u8; 32],
			&self.sender_pub_info_1.pk,
			cs.clone(),
		);
		prf_circuit_helper(
			false,
			&self.sender_priv_info_1.sk,
			&self.sender_pub_info_1.rho,
			&self.sender_priv_info_1.sn,
			cs.clone(),
		);
		prf_circuit_helper(
			true,
			&self.sender_priv_info_2.sk,
			&[0u8; 32],
			&self.sender_pub_info_2.pk,
			cs.clone(),
		);
		prf_circuit_helper(
			false,
			&self.sender_priv_info_2.sk,
			&self.sender_pub_info_2.rho,
			&self.sender_priv_info_2.sn,
			cs.clone(),
		);

		// 3. sender's commitment is in List_all
		// Allocate Parameters for CRH
		let param_var = HashParamVar::new_constant(
			ark_relations::ns!(cs, "new_parameter"),
			self.hash_param.clone(),
		)
		.unwrap();

		merkle_membership_circuit_proof(
			&self.sender_coin_1.cm_bytes,
			&self.sender_membership_1,
			param_var.clone(),
			self.root_1,
			cs.clone(),
		);

		merkle_membership_circuit_proof(
			&self.sender_coin_2.cm_bytes,
			&self.sender_membership_2,
			param_var,
			self.root_2,
			cs.clone(),
		);

		// 4. sender's and receiver's total value are the same
		// TODO: do we need to check that the values are all positive?
		// seems that Rust's type system has already eliminated negative values
		let sender_value_1_fq = Fq::from(self.sender_priv_info_1.value);
		let mut sender_value_sum =
			FqVar::new_witness(ark_relations::ns!(cs, "sender value"), || {
				Ok(&sender_value_1_fq)
			})
			.unwrap();
		let sender_value_2_fq = Fq::from(self.sender_priv_info_2.value);
		let sender_value_2_var = FqVar::new_witness(ark_relations::ns!(cs, "sender value"), || {
			Ok(&sender_value_2_fq)
		})
		.unwrap();
		sender_value_sum += sender_value_2_var;

		let receiver_value_1_fq = Fq::from(self.receiver_value_1);
		let mut receiver_value_sum =
			FqVar::new_witness(ark_relations::ns!(cs, "receiver value"), || {
				Ok(&receiver_value_1_fq)
			})
			.unwrap();
		let receiver_value_2_fq = Fq::from(self.receiver_value_2);
		let receiver_value_2_var =
			FqVar::new_witness(ark_relations::ns!(cs, "receiver value"), || {
				Ok(&receiver_value_2_fq)
			})
			.unwrap();
		receiver_value_sum += receiver_value_2_var;

		sender_value_sum.enforce_equal(&receiver_value_sum).unwrap();

		Ok(())
	}
}

// =============================
// circuit for the following statements
// 1. k = com(pk||rho, r)
// 2. cm = com(v||k, s)
// for the sender, the cm is hidden and k is public
// =============================
pub(crate) fn sender_token_well_formed_circuit_helper(
	parameters_var: &CommitmentParamVar,
	coin: &MantaCoin,
	pub_info: &MantaCoinPubInfo,
	value: u64,
	cs: ConstraintSystemRef<Fq>,
) {
	// =============================
	// statement 1: k = com(pk||rho, r)
	// =============================
	let input: Vec<u8> = [pub_info.pk.as_ref(), pub_info.rho.as_ref()].concat();
	let mut input_var = Vec::new();
	for byte in &input {
		input_var.push(UInt8::new_witness(cs.clone(), || Ok(*byte)).unwrap());
	}

	// opening
	let r = Fr::deserialize(pub_info.r.as_ref()).unwrap();
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
	let k = CommitmentOutput::deserialize(pub_info.k.as_ref()).unwrap();
	let commitment_var2 = MantaCoinCommitmentOutputVar::new_input(
		ark_relations::ns!(cs, "gadget_commitment"),
		|| Ok(k),
	)
	.unwrap();
	result_var.enforce_equal(&commitment_var2).unwrap();

	// =============================
	// statement 2: cm = com(v||k, s)
	// =============================
	let input: Vec<u8> = [value.to_le_bytes().as_ref(), pub_info.k.as_ref()].concat();
	let mut input_var = Vec::new();
	for byte in &input {
		input_var.push(UInt8::new_witness(cs.clone(), || Ok(*byte)).unwrap());
	}

	// opening
	let s = Randomness::<EdwardsProjective>(Fr::deserialize(pub_info.s.as_ref()).unwrap());
	let randomness_var = MantaCoinCommitmentOpenVar::new_witness(
		ark_relations::ns!(cs, "gadget_randomness"),
		|| Ok(&s),
	)
	.unwrap();

	// commitment
	let result_var: MantaCoinCommitmentOutputVar =
		CommitmentSchemeVar::commit(&parameters_var, &input_var, &randomness_var).unwrap();

	// the other commitment
	let cm: CommitmentOutput = CommitmentOutput::deserialize(coin.cm_bytes.as_ref()).unwrap();
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
	coin: &MantaCoin,
	k: &[u8; 32],
	s: &[u8; 32],
	value: u64,
	cs: ConstraintSystemRef<Fq>,
) {
	// =============================
	// statement 1: cm = com(v||k, s)
	// =============================
	let input: Vec<u8> = [value.to_le_bytes().as_ref(), k].concat();
	let mut input_var = Vec::new();
	for byte in &input {
		input_var.push(UInt8::new_witness(cs.clone(), || Ok(*byte)).unwrap());
	}

	// opening
	let s = Randomness::<EdwardsProjective>(Fr::deserialize(s.as_ref()).unwrap());
	let randomness_var = MantaCoinCommitmentOpenVar::new_witness(
		ark_relations::ns!(cs, "gadget_randomness"),
		|| Ok(&s),
	)
	.unwrap();

	// commitment
	let result_var: MantaCoinCommitmentOutputVar =
		CommitmentSchemeVar::commit(&parameters_var, &input_var, &randomness_var).unwrap();

	// the other commitment
	let cm: CommitmentOutput = CommitmentOutput::deserialize(coin.cm_bytes.as_ref()).unwrap();
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
