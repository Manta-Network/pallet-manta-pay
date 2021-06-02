// use super::*;
// use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// use ark_std::io::{Read, Write};

// impl MantaSerDes for SenderMetaData {
// 	fn serialize<W: Write>(&self, mut writer: W) {
// 		self.asset.serialize(&mut writer);
// 		self.root.serialize(&mut writer);
// 		self.membership.auth_path;
// 	}

// 	fn deserialize<R: Read>(mut reader: R) -> Self {
// 		let asset = MantaAsset::deserialize(&mut reader);
// 		let root = LedgerMerkleTreeRoot::deserialize(&mut reader);
// 		let membership = AccountMembership::deserialize(&mut reader);

// 		Self {
// 			asset,
// 			root,
// 			membership,
// 		}
// 	}
// }
