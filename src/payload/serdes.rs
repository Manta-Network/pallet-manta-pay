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
use ark_std::io::{Read, Write};
use manta_error::MantaError;

impl MantaSerDes for MintData {
	/// Serialize the mint data into an array of 104 bytes.
	fn serialize<W: Write>(&self, mut writer: W) -> Result<(), MantaError> {
		writer.write_all(&(self.asset_id as u64).to_le_bytes())?;
		writer.write_all(self.amount.to_le_bytes().as_ref())?;
		writer.write_all(&self.cm)?;
		writer.write_all(&self.k)?;
		writer.write_all(&self.s)?;
		Ok(())
	}

	/// Deserialize an array of 104 bytes into a MintData.
	fn deserialize<R: Read>(mut reader: R) -> Result<Self, MantaError> {
		let mut data = MintData::default();

		let mut buf1 = [0u8; 8];
		let mut buf2 = [0u8; 8];
		reader.read_exact(buf1.as_mut())?;
		data.asset_id = u64::from_le_bytes(buf1);

		reader.read_exact(buf2.as_mut())?;
		data.amount = u64::from_le_bytes(buf2);

		reader.read_exact(&mut data.cm)?;
		reader.read_exact(&mut data.k)?;
		reader.read_exact(&mut data.s)?;
		Ok(data)
	}
}

impl MantaSerDes for PrivateTransferData {
	/// Serialize the private transfer data
	fn serialize<W: Write>(&self, mut writer: W) -> Result<(), MantaError> {
		self.sender_1.serialize(&mut writer)?;
		self.sender_2.serialize(&mut writer)?;
		self.receiver_1.serialize(&mut writer)?;
		self.receiver_2.serialize(&mut writer)?;
		writer.write_all(&self.proof.as_ref())?;
		Ok(())
	}

	/// Deserialize the private transfer data
	fn deserialize<R: Read>(mut reader: R) -> Result<Self, MantaError> {
		let sender_1 = SenderData::deserialize(&mut reader)?;
		let sender_2 = SenderData::deserialize(&mut reader)?;
		let receiver_1 = ReceiverData::deserialize(&mut reader)?;
		let receiver_2 = ReceiverData::deserialize(&mut reader)?;

		let mut proof = [0u8; 192];
		reader.read_exact(proof.as_mut())?;

		Ok(Self {
			sender_1,
			sender_2,
			receiver_1,
			receiver_2,
			proof,
		})
	}
}

impl MantaSerDes for ReclaimData {
	/// Serialize the private transfer data
	fn serialize<W: Write>(&self, mut writer: W) -> Result<(), MantaError> {
		writer.write_all(&(self.asset_id as u64).to_le_bytes())?;
		writer.write_all(self.reclaim_amount.to_le_bytes().as_ref())?;
		self.sender_1.serialize(&mut writer)?;
		self.sender_2.serialize(&mut writer)?;
		self.receiver.serialize(&mut writer)?;
		writer.write_all(&self.proof.as_ref())?;

		Ok(())
	}

	/// Deserialize the private transfer data
	fn deserialize<R: Read>(mut reader: R) -> Result<Self, MantaError> {
		let mut data = ReclaimData::default();

		let mut buf = [0u8; 8];
		reader.read_exact(buf.as_mut())?;
		data.asset_id = u64::from_le_bytes(buf);

		reader.read_exact(buf.as_mut())?;
		data.reclaim_amount = u64::from_le_bytes(buf);

		data.sender_1 = SenderData::deserialize(&mut reader)?;
		data.sender_2 = SenderData::deserialize(&mut reader)?;
		data.receiver = ReceiverData::deserialize(&mut reader)?;

		let mut buf = [0u8; 192];
		reader.read_exact(&mut buf)?;
		data.proof.copy_from_slice(buf.as_ref());

		Ok(data)
	}
}

impl MantaSerDes for SenderData {
	/// Serialize the sender data into an array of 64 bytes.
	fn serialize<W: Write>(&self, mut writer: W) -> Result<(), MantaError> {
		writer.write_all(&self.k)?;
		writer.write_all(&self.void_number)?;
		writer.write_all(&self.root)?;
		Ok(())
	}

	/// Deserialize an array of 64 bytes into a SenderData.
	fn deserialize<R: Read>(mut reader: R) -> Result<Self, MantaError> {
		let mut data = SenderData::default();
		reader.read_exact(&mut data.k)?;
		reader.read_exact(&mut data.void_number)?;
		reader.read_exact(&mut data.root)?;
		Ok(data)
	}
}

impl MantaSerDes for ReceiverData {
	/// Serialize the receiver data into an array of 80 bytes.
	fn serialize<W: Write>(&self, mut writer: W) -> Result<(), MantaError> {
		writer.write_all(&self.k)?;
		writer.write_all(&self.cm)?;
		writer.write_all(&self.sender_pk)?;
		writer.write_all(&self.cipher)?;
		Ok(())
	}

	/// Deserialize an array of 80 bytes into a receiver data.
	fn deserialize<R: Read>(mut reader: R) -> Result<Self, MantaError> {
		let mut data = ReceiverData::default();
		reader.read_exact(&mut data.k)?;
		reader.read_exact(&mut data.cm)?;
		reader.read_exact(&mut data.sender_pk)?;
		reader.read_exact(&mut data.cipher)?;
		Ok(data)
	}
}
