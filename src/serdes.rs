use crate::{manta_token::*, param::*};
use ark_crypto_primitives::{commitment, crh};
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::io::{Read, Write};
use blake2::{Blake2s, Digest};
use sp_std::vec::Vec;

pub trait MantaSerDes {
	fn serialize<W: Write>(&self, writer: W);
	fn deserialize<R: Read>(reader: R) -> Self;
}

pub trait Checksum {
	fn get_checksum(&self) -> [u8; 32];
}

impl MantaSerDes for crh::pedersen::Parameters<EdwardsProjective> {
	/// serialize the hash parameters without compression
	fn serialize<W: Write>(&self, mut writer: W) {
		for generaters in self.generators.iter() {
			for gen in generaters {
				gen.serialize_uncompressed(&mut writer).unwrap()
			}
		}
	}

	/// This function deserialize the hash parameters.
	/// warning: for efficiency reasons, we do not check the validity of deserialized elements
	/// the caller should check the CheckSum of the parameters to make sure
	/// they are consistent with the version used by the ledger.
	fn deserialize<R: Read>(mut reader: R) -> Self {
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

		Self { generators }
	}
}

impl MantaSerDes for commitment::pedersen::Parameters<EdwardsProjective> {
	/// serialize the commitment parameters without compression
	fn serialize<W: Write>(&self, mut writer: W) {
		for generaters in self.generators.iter() {
			for gen in generaters {
				gen.serialize_uncompressed(&mut writer).unwrap()
			}
		}
		for rgen in self.randomness_generator.iter() {
			rgen.serialize_uncompressed(&mut writer).unwrap()
		}
	}

	/// This function deserialize the hash parameters.
	/// warning: for efficiency reasons, we do not check the validity of deserialized elements
	/// the caller should check the CheckSum of the parameters to make sure
	/// they are consistent with the version used by the ledger.
	fn deserialize<R: Read>(mut reader: R) -> Self {
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
			randomness_generator
				.push(EdwardsProjective::deserialize_unchecked(&mut reader).unwrap())
		}

		Self {
			randomness_generator,
			generators,
		}
	}
}

impl MantaSerDes for MintData {
	/// serialize the mint data into an array of 96 bytes
	fn serialize<W: Write>(&self, mut writer: W) {
		writer.write_all(&self.cm).unwrap();
		writer.write_all(&self.k).unwrap();
		writer.write_all(&self.s).unwrap();
	}

	/// deserialize an array of 96 bytes into a MintData
	fn deserialize<R: Read>(mut reader: R) -> Self {
		let mut data = MintData::default();
		reader.read_exact(&mut data.cm).unwrap();
		reader.read_exact(&mut data.k).unwrap();
		reader.read_exact(&mut data.s).unwrap();
		data
	}
}

impl MantaSerDes for SenderData {
	/// serialize the sender data into an array of 64 bytes
	fn serialize<W: Write>(&self, mut writer: W) {
		writer.write_all(&self.k).unwrap();
		writer.write_all(&self.sn).unwrap();
	}

	/// deserialize an array of 64 bytes into a SenderData
	fn deserialize<R: Read>(mut reader: R) -> Self {
		let mut data = SenderData::default();
		reader.read_exact(&mut data.k).unwrap();
		reader.read_exact(&mut data.sn).unwrap();
		data
	}
}

impl MantaSerDes for ReceiverData {
	/// serialize the receiver data into an array of 80 bytes
	fn serialize<W: Write>(&self, mut writer: W) {
		writer.write_all(&self.k).unwrap();
		writer.write_all(&self.cm).unwrap();
		writer.write_all(&self.cipher).unwrap();
	}

	/// deserialize an array of 80 bytes into a receiver data
	fn deserialize<R: Read>(mut reader: R) -> Self {
		let mut data = ReceiverData::default();
		reader.read_exact(&mut data.k).unwrap();
		reader.read_exact(&mut data.cm).unwrap();
		reader.read_exact(&mut data.cipher).unwrap();
		data
	}
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
