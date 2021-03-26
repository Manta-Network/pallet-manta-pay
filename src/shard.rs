use crate::param::*;
use frame_support::codec::{Decode, Encode};

/// a shard is a list of commitment, and a merkle root of this list
#[derive(Encode, Debug, Decode, Clone, Default, PartialEq)]
pub struct Shard {
	pub list: Vec<[u8; 32]>,
	pub root: [u8; 32],
}

/// a Shards is a list of shard-s
#[derive(Encode, Debug, Decode, Clone, PartialEq)]
pub struct Shards {
	pub shard: [Shard; 256],
}

pub trait LedgerSharding {
	type Commitment;
	type Root;
	type Param;

	/// root exists in thie current shards
	fn check_root(&self, target: &Self::Root) -> bool;

	/// the commitment exists in the current shards
	fn exist(&self, target: &Self::Commitment) -> bool;

	/// update the shards with a new commitment
	fn update(&mut self, target: &Self::Commitment, param: Self::Param);
}

impl LedgerSharding for Shards {
	type Commitment = [u8; 32];
	type Root = [u8; 32];
	type Param = HashParam;

	// root exists in thie current shards
	fn check_root(&self, target: &Self::Root) -> bool {
		for shard in self.shard.iter() {
			if shard.root == *target {
				return true;
			}
		}
		false
	}

	fn exist(&self, target: &Self::Commitment) -> bool {
		// the index of the shard is determined by the first byte of the cm
		let shard_index = target[0] as usize;

		for e in self.shard[shard_index].list.iter() {
			if e == target {
				return true;
			}
		}
		false
	}

	// this function updates the ledger shards,
	// this function does not check if target already exists in the list or not
	fn update(&mut self, target: &Self::Commitment, param: Self::Param) {
		// the index of the shard is determined by the first byte of the cm
		let shard_index = target[0] as usize;

		// update the list, and the root accordingly
		self.shard[shard_index].list.push(*target);
		self.shard[shard_index].root =
			crate::crypto::merkle_root(param, &self.shard[shard_index].list);
	}
}

impl Default for Shards {
	fn default() -> Self {
		// is there a non-std macro for this?
		// this code is really stupid LOL
		let tmp = [
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
			Shard::default(),
		];

		Self { shard: tmp }
	}
}
