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

use super::*;
use ark_ed_on_bls12_381::Fq;
use manta_crypto::*;

impl MantaZKPVerifier for PrivateTransferData {
	type VerificationKey = VerificationKey;
	/// This algorithm verifies the ZKP, given the verification key and the data.
	fn verify(&self, transfer_key_bytes: &VerificationKey) -> bool {
		let buf: &[u8] = transfer_key_bytes.data;
		let vk = Groth16Vk::deserialize_unchecked(buf).unwrap();
		let pvk = Groth16Pvk::from(vk);
		let proof = Groth16Proof::deserialize(self.proof.as_ref()).unwrap();
		let k_old_1 = CommitmentOutput::deserialize(self.sender_1.k.as_ref()).unwrap();
		let k_old_2 = CommitmentOutput::deserialize(self.sender_2.k.as_ref()).unwrap();
		let cm_new_1 = CommitmentOutput::deserialize(self.receiver_1.cm.as_ref()).unwrap();
		let cm_new_2 = CommitmentOutput::deserialize(self.receiver_2.cm.as_ref()).unwrap();
		let merkle_root_1 = HashOutput::deserialize(self.sender_1.root.as_ref()).unwrap();
		let merkle_root_2 = HashOutput::deserialize(self.sender_2.root.as_ref()).unwrap();

		let mut inputs = [
			k_old_1.x, k_old_1.y, // sender coin 1
			k_old_2.x, k_old_2.y, // sender coin 2
			cm_new_1.x, cm_new_1.y, // receiver coin 1
			cm_new_2.x, cm_new_2.y, // receiver coin 2
		]
		.to_vec();
		let sn_1: Vec<Fq> =
			ToConstraintField::<Fq>::to_field_elements(self.sender_1.void_number.as_ref()).unwrap();
		let sn_2: Vec<Fq> =
			ToConstraintField::<Fq>::to_field_elements(self.sender_2.void_number.as_ref()).unwrap();

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
}

impl MantaZKPVerifier for ReclaimData {
	type VerificationKey = VerificationKey;

	/// This algorithm verifies the ZKP, given the verification key and the data.
	fn verify(&self, reclaim_key_bytes: &VerificationKey) -> bool {
		let buf: &[u8] = reclaim_key_bytes.data;
		let vk = Groth16Vk::deserialize_unchecked(buf).unwrap();
		let pvk = Groth16Pvk::from(vk);
		let proof = Groth16Proof::deserialize(self.proof.as_ref()).unwrap();
		let k_old_1 = CommitmentOutput::deserialize(self.sender_1.k.as_ref()).unwrap();
		let k_old_2 = CommitmentOutput::deserialize(self.sender_2.k.as_ref()).unwrap();
		let cm_new = CommitmentOutput::deserialize(self.receiver.cm.as_ref()).unwrap();
		let merkle_root_1 = HashOutput::deserialize(self.sender_1.root.as_ref()).unwrap();
		let merkle_root_2 = HashOutput::deserialize(self.sender_2.root.as_ref()).unwrap();

		let mut inputs = [
			k_old_1.x, k_old_1.y, // sender coin 1
			k_old_2.x, k_old_2.y, // sender coin 2
			cm_new.x, cm_new.y, // receiver coin
		]
		.to_vec();
		let sn_1: Vec<Fq> =
			ToConstraintField::<Fq>::to_field_elements(self.sender_1.void_number.as_ref()).unwrap();
		let sn_2: Vec<Fq> =
			ToConstraintField::<Fq>::to_field_elements(self.sender_2.void_number.as_ref()).unwrap();

		let mr_1: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&merkle_root_1).unwrap();
		let mr_2: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&merkle_root_2).unwrap();
		let value_fq = Fq::from(self.reclaim_amount);
		let asset_id_fq = Fq::from(self.asset_id as u64);
		inputs = [
			inputs[..].as_ref(),
			sn_1.as_ref(),
			sn_2.as_ref(),
			mr_1.as_ref(),
			mr_2.as_ref(),
			[value_fq].as_ref(),
			[asset_id_fq].as_ref(),
		]
		.concat();

		verify_proof(&pvk, &proof, &inputs[..]).unwrap()
	}
}
