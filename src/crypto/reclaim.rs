use crate::{coin::*, param::*};
use ark_ed_on_bls12_381::{constraints::FqVar, Fq};
use ark_r1cs_std::{alloc::AllocVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

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
	pub sender_coin: MantaCoin,
	pub sender_pub_info: MantaCoinPubInfo,
	pub sender_priv_info: MantaCoinPrivInfo,

	// amount
	pub value: u64,

	// ledger
	pub list: Vec<[u8; 32]>,
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

		super::transfer::token_well_formed_circuit_helper(
			true,
			&parameters_var,
			&self.sender_coin,
			&self.sender_pub_info,
			self.sender_priv_info.value,
			cs.clone(),
		);

		// 2. address and the secret key derives public key
		//  sender.pk = PRF(sender_sk, [0u8;32])
		//  sender.sn = PRF(sender_sk, rho)
		super::transfer::prf_circuit_helper(
			true,
			&self.sender_priv_info.sk,
			&[0u8; 32],
			&self.sender_pub_info.pk,
			cs.clone(),
		);
		super::transfer::prf_circuit_helper(
			false,
			&self.sender_priv_info.sk,
			&self.sender_pub_info.rho,
			&self.sender_priv_info.sn,
			cs.clone(),
		);

		// // 3. sender's commitment is in List_all
		// super::transfer::merkle_membership_circuit_proof(
		// 	&self.hash_param,
		// 	&self.sender_coin.cm_bytes,
		// 	&self.list,
		// 	cs.clone(),
		// );

		// 4. sender's value is the same as reclaimed value
		let value_fq = Fq::from(self.value);
		let value_var =
			FqVar::new_input(ark_relations::ns!(cs, "sender value"), || Ok(&value_fq)).unwrap();

		let value_fq2 = Fq::from(self.sender_priv_info.value);
		let value_var2 =
			FqVar::new_witness(ark_relations::ns!(cs, "sender value"), || Ok(&value_fq2)).unwrap();

		value_var.enforce_equal(&value_var2).unwrap();

		Ok(())
	}
}
