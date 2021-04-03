use super::transfer::*;
use crate::{coin::*, param::*};
use ark_ed_on_bls12_381::{constraints::FqVar, Fq};
use ark_r1cs_std::{alloc::AllocVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
// use ark_std::vec::Vec;

// =============================
// circuit for the following statements
// 1. sender's coin is well-formed
//  1.1 k = com(pk||rho, r)
//  1.2 cm = com(v||k, s)
// where only k is public
// 2. address and the secret key derives public key
//  sender.pk = PRF(sender_sk, [0u8;32])
// 3. sender's commitment is in List_all
//  NOTE: we de not need to prove that sender's sn is not in List_used
//        this can be done in the public
// 4. sender's value matches input value
// =============================
#[derive(Clone)]
pub struct ReclaimCircuit {
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
	pub receiver_coin: MantaCoin,
	pub receiver_pub_info: MantaCoinPubInfo,
	pub receiver_value: u64,

	// reclaimed amount
	pub reclaim_value: u64,
}

impl ConstraintSynthesizer<Fq> for ReclaimCircuit {
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
			&self.receiver_coin,
			&self.receiver_pub_info,
			self.receiver_value,
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

		let receiver_value_fq = Fq::from(self.receiver_value);
		let mut receiver_value_sum =
			FqVar::new_witness(ark_relations::ns!(cs, "receiver value"), || {
				Ok(&receiver_value_fq)
			})
			.unwrap();
		let reclaim_value_fq = Fq::from(self.reclaim_value);
		let reclaim_value_var = FqVar::new_input(ark_relations::ns!(cs, "reclaimed value"), || {
			Ok(&reclaim_value_fq)
		})
		.unwrap();
		receiver_value_sum += reclaim_value_var;

		sender_value_sum.enforce_equal(&receiver_value_sum).unwrap();

		Ok(())
	}
}
