use crate::param::*;
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::io::{Read, Write};
use blake2::{Blake2s, Digest};
use sp_std::vec::Vec;

/// serialize the hash parameters without compression
pub fn hash_param_serialize<W: Write>(hash_param: &HashParam, mut writer: W) {
	for generaters in hash_param.generators.iter() {
		for gen in generaters {
			gen.serialize_uncompressed(&mut writer).unwrap()
		}
	}
}

/// This function deserialize the hash parameters.
/// warning: for efficiency reasons, we do not check the validity of deserialized elements
/// the caller should check the CheckSum of the parameters to make sure
/// they are consistent with the version used by the ledger.
pub fn hash_param_deserialize<R: Read>(mut reader: R) -> HashParam {
	let window = PERDERSON_WINDOW_SIZE;
	let len = PERDERSON_WINDOW_NUM;

	let mut generators = Vec::new();
	for _ in 0..len {
		let mut gen = Vec::new();
		for _ in 0..window {
			gen.push(EdwardsProjective::deserialize_unchecked(&mut reader).unwrap())
		}
		generators.push(gen);
	}

	HashParam { generators }
}

pub fn hash_param_checksum(hash_param: &HashParam) -> [u8; 32] {
	let mut buf: Vec<u8> = Vec::new();
	hash_param_serialize(&hash_param, &mut buf);
	let mut hasher = Blake2s::new();
	hasher.update(buf);
	let digest = hasher.finalize();
	let mut res = [0u8; 32];
	res.copy_from_slice(digest.as_slice());
	res
}

/// serialize the commitment parameters without compression
pub fn commit_param_serialize<W: Write>(com_param: &MantaCoinCommitmentParam, mut writer: W) {
	for generaters in com_param.generators.iter() {
		for gen in generaters {
			gen.serialize_uncompressed(&mut writer).unwrap()
		}
	}
	for rgen in com_param.randomness_generator.iter() {
		rgen.serialize_uncompressed(&mut writer).unwrap()
	}
}

/// This function deserialize the hash parameters.
/// warning: for efficiency reasons, we do not check the validity of deserialized elements
/// the caller should check the CheckSum of the parameters to make sure
/// they are consistent with the version used by the ledger.
pub fn commit_param_deserialize<R: Read>(mut reader: R) -> MantaCoinCommitmentParam {
	let window = PERDERSON_WINDOW_SIZE;
	let len = PERDERSON_WINDOW_NUM;

	let mut generators = Vec::new();
	for _ in 0..len {
		let mut gen = Vec::new();
		for _ in 0..window {
			gen.push(EdwardsProjective::deserialize_unchecked(&mut reader).unwrap())
		}
		generators.push(gen);
	}
	let mut randomness_generator = Vec::new();
	for _ in 0..252 {
		randomness_generator.push(EdwardsProjective::deserialize_unchecked(&mut reader).unwrap())
	}

	MantaCoinCommitmentParam {
		generators,
		randomness_generator,
	}
}

pub fn commit_param_checksum(commit_param: &MantaCoinCommitmentParam) -> [u8; 32] {
	let mut buf: Vec<u8> = Vec::new();
	commit_param_serialize(&commit_param, &mut buf);
	let mut hasher = Blake2s::new();
	hasher.update(buf);
	let digest = hasher.finalize();
	let mut res = [0u8; 32];
	res.copy_from_slice(digest.as_slice());
	res
}
