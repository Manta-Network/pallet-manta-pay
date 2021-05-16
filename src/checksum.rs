
use crate::{param::*};
use ark_crypto_primitives::{commitment, crh};
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_std::{
	vec::Vec,
};
use blake2::{Blake2s, Digest};
use crate::serdes::MantaSerDes;

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