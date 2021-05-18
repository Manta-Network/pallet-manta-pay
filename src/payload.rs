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

use ark_std::io::{Read, Write};
use frame_support::codec::{Decode, Encode};
use manta_crypto::{Commitment, CommitmentParam, MantaCrypto, MantaSerDes};

/// Input data to a mint function.
#[derive(Encode, Debug, Decode, Clone, Default, PartialEq)]
pub struct MintData {
	pub cm: [u8; 32],
	pub k: [u8; 32],
	pub s: [u8; 32],
}

impl MintData {
	pub(crate) fn sanity_check(&self, value: u64, param: &CommitmentParam) -> bool {
		let payload = [value.to_le_bytes().as_ref(), self.k.as_ref()].concat();
		<MantaCrypto as Commitment>::check_commitment(&param, &payload, &self.s, &self.cm)
	}
}

/// Data required for a sender to spend a coin.
#[derive(Encode, Debug, Decode, Clone, Default, PartialEq)]
pub struct SenderData {
	pub k: [u8; 32],
	pub sn: [u8; 32],
	pub root: [u8; 32],
}

/// Data required for a receiver to receive a coin.
#[derive(Encode, Debug, Decode, Clone, Default, PartialEq)]
pub struct ReceiverData {
	pub k: [u8; 32],
	pub cm: [u8; 32],
	pub cipher: [u8; 16],
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
