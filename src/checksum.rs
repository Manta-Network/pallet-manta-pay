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

use crate::{param::*, serdes::MantaSerDes};
use ark_crypto_primitives::{commitment, crh};
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_std::vec::Vec;
use blake2::{Blake2s, Digest};

/// Manta's native checksum trait.
pub trait Checksum {
	/// Generate a unique checksum for a give data struct.
	fn get_checksum(&self) -> [u8; 32];
}
impl Checksum for crh::pedersen::Parameters<EdwardsProjective> {
	fn get_checksum(&self) -> [u8; 32] {
		let mut buf: Vec<u8> = Vec::new();
		self.serialize(&mut buf);
		let mut hasher = Blake2s::new();
		hasher.update(buf);
		let digest = hasher.finalize();
		let mut res = [0u8; 32];
		res.copy_from_slice(digest.as_slice());
		res
	}
}

impl Checksum for commitment::pedersen::Parameters<EdwardsProjective> {
	fn get_checksum(&self) -> [u8; 32] {
		let mut buf: Vec<u8> = Vec::new();
		self.serialize(&mut buf);
		let mut hasher = Blake2s::new();
		hasher.update(buf);
		let digest = hasher.finalize();
		let mut res = [0u8; 32];
		res.copy_from_slice(digest.as_slice());
		res
	}
}

impl Checksum for VerificationKey {
	fn get_checksum(&self) -> [u8; 32] {
		let mut hasher = Blake2s::new();
		hasher.update(&self.data);
		let digest = hasher.finalize();
		let mut res = [0u8; 32];
		res.copy_from_slice(digest.as_slice());
		res
	}
}

impl Checksum for Parameter {
	fn get_checksum(&self) -> [u8; 32] {
		let mut hasher = Blake2s::new();
		hasher.update(&self.data);
		let digest = hasher.finalize();
		let mut res = [0u8; 32];
		res.copy_from_slice(digest.as_slice());
		res
	}
}
