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
use ark_crypto_primitives::{commitment, crh};
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
	io::{Read, Write},
	vec::Vec,
};

/// Manta's native (de)serialization trait.
pub trait MantaSerDes {
	/// Serialize a struct into a writable blob.
	fn serialize<W: Write>(&self, writer: W);
	/// Deserialize a readable data into a struct.
	fn deserialize<R: Read>(reader: R) -> Self;
}



impl MantaSerDes for crh::pedersen::Parameters<EdwardsProjective> {
	/// serialize the hash parameters without compression
	fn serialize<W: Write>(&self, mut writer: W) {
		for generators in self.generators.iter() {
			for gen in generators {
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
	/// Serialize the commitment parameters without data compression.
	fn serialize<W: Write>(&self, mut writer: W) {
		for generators in self.generators.iter() {
			for gen in generators {
				gen.serialize_uncompressed(&mut writer).unwrap()
			}
		}
		for rgen in self.randomness_generator.iter() {
			rgen.serialize_uncompressed(&mut writer).unwrap()
		}
	}

	/// This function deserialize the hash parameters.
	/// __Warning__: for efficiency reasons, we do not check the validity of deserialized elements.
	/// The caller should check the CheckSum of the parameters to make sure
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
	/// Serialize the mint data into an array of 96 bytes.
	fn serialize<W: Write>(&self, mut writer: W) {
		writer.write_all(&self.cm).unwrap();
		writer.write_all(&self.k).unwrap();
		writer.write_all(&self.s).unwrap();
	}

	/// Deserialize an array of 96 bytes into a MintData.
	fn deserialize<R: Read>(mut reader: R) -> Self {
		let mut data = MintData::default();
		reader.read_exact(&mut data.cm).unwrap();
		reader.read_exact(&mut data.k).unwrap();
		reader.read_exact(&mut data.s).unwrap();
		data
	}
}

impl MantaSerDes for SenderData {
	/// Serialize the sender data into an array of 64 bytes.
	fn serialize<W: Write>(&self, mut writer: W) {
		writer.write_all(&self.k).unwrap();
		writer.write_all(&self.sn).unwrap();
		writer.write_all(&self.root).unwrap();
	}

	/// Deserialize an array of 64 bytes into a SenderData.
	fn deserialize<R: Read>(mut reader: R) -> Self {
		let mut data = SenderData::default();
		reader.read_exact(&mut data.k).unwrap();
		reader.read_exact(&mut data.sn).unwrap();
		reader.read_exact(&mut data.root).unwrap();
		data
	}
}

impl MantaSerDes for ReceiverData {
	/// Serialize the receiver data into an array of 80 bytes.
	fn serialize<W: Write>(&self, mut writer: W) {
		writer.write_all(&self.k).unwrap();
		writer.write_all(&self.cm).unwrap();
		writer.write_all(&self.cipher).unwrap();
	}

	/// Deserialize an array of 80 bytes into a receiver data.
	fn deserialize<R: Read>(mut reader: R) -> Self {
		let mut data = ReceiverData::default();
		reader.read_exact(&mut data.k).unwrap();
		reader.read_exact(&mut data.cm).unwrap();
		reader.read_exact(&mut data.cipher).unwrap();
		data
	}
}
