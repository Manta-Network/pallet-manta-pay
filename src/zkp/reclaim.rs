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

use super::transfer::*;
use ark_ed_on_bls12_381::{constraints::FqVar, Fq};
use ark_r1cs_std::{alloc::AllocVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use manta_crypto::*;
use pallet_manta_asset::*;

// =============================
/// ZK circuit for the __reclaim__ statements.
/// # <weight>
/// 1. sender's coin is well-formed:
///   * `k = com(pk||rho, r)`
///   * `cm = com(v||k, s)`
/// where only k is public.
/// 2. receiver's coin is well-formed:
///   * `cm = com(v||k, s)`
/// where both `k` and `cm` are public.
/// 3. address and the secret key derives public key:
///  `sender.pk = PRF(sender_sk, [0u8;32])`
/// 4. sender's commitment is in CMList.
///  NOTE: we do not need to prove that sender's vn is not in VNList.
///        this can be done in the public.
/// 5. sender's total value == receiver value + reclaim value.
/// # </weight>
// =============================
#[derive(Clone)]
pub struct ReclaimCircuit {
	// param
	pub commit_param: CommitmentParam,
	pub hash_param: HashParam,

	// sender
	pub sender_1: MantaAsset,
	pub sender_membership_1: AccountMembership,
	pub root_1: LedgerMerkleTreeRoot,

	pub sender_2: MantaAsset,
	pub sender_membership_2: AccountMembership,
	pub root_2: LedgerMerkleTreeRoot,

	// receiver
	pub receiver: MantaAssetProcessedReceiver,

	// reclaimed amount
	pub reclaim_value: u64,
}

impl ConstraintSynthesizer<Fq> for ReclaimCircuit {
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

		sender_token_well_formed_circuit_helper(&parameters_var, &self.sender_1, cs.clone());

		sender_token_well_formed_circuit_helper(&parameters_var, &self.sender_2, cs.clone());

		receiver_token_well_formed_circuit_helper(&parameters_var, &self.receiver, cs.clone());

		// 2. address and the secret key derives public key
		//  sender.pk = PRF(sender_sk, [0u8;32])
		//  sender.sn = PRF(sender_sk, rho)
		prf_circuit_helper(
			true,
			&self.sender_1.priv_info.sk,
			&[0u8; 32],
			&self.sender_1.pub_info.pk,
			cs.clone(),
		);
		prf_circuit_helper(
			false,
			&self.sender_1.priv_info.sk,
			&self.sender_1.pub_info.rho,
			&self.sender_1.void_number,
			cs.clone(),
		);
		prf_circuit_helper(
			true,
			&self.sender_2.priv_info.sk,
			&[0u8; 32],
			&self.sender_2.pub_info.pk,
			cs.clone(),
		);
		prf_circuit_helper(
			false,
			&self.sender_2.priv_info.sk,
			&self.sender_2.pub_info.rho,
			&self.sender_2.void_number,
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
			&self.sender_1.commitment,
			&self.sender_membership_1,
			param_var.clone(),
			self.root_1,
			cs.clone(),
		);

		merkle_membership_circuit_proof(
			&self.sender_2.commitment,
			&self.sender_membership_2,
			param_var,
			self.root_2,
			cs.clone(),
		);

		// 4. sender's and receiver's total value are the same
		// TODO: do we need to check that the values are all positive?
		// seems that Rust's type system has already eliminated negative values
		let sender_value_1_fq = Fq::from(self.sender_1.priv_info.value);
		let mut sender_value_sum =
			FqVar::new_witness(ark_relations::ns!(cs, "sender value"), || {
				Ok(&sender_value_1_fq)
			})
			.unwrap();
		let sender_value_2_fq = Fq::from(self.sender_2.priv_info.value);
		let sender_value_2_var = FqVar::new_witness(ark_relations::ns!(cs, "sender value"), || {
			Ok(&sender_value_2_fq)
		})
		.unwrap();
		sender_value_sum += sender_value_2_var;

		let receiver_value_fq = Fq::from(self.receiver.value);
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
