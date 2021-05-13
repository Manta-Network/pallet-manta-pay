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

use crate::param::*;
use ark_crypto_primitives::{
	commitment::pedersen::Randomness, CommitmentScheme as ArkCommitmentScheme,
};
use ark_ed_on_bls12_381::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub(crate) fn comm_open(
	com_param: &CommitmentParam,
	randomness: &[u8; 32],
	payload: &[u8],
	commitment: &[u8; 32],
) -> bool {
	let open = Randomness(Fr::deserialize(randomness.as_ref()).unwrap());
	let cm = CommitmentOutput::deserialize(commitment.as_ref()).unwrap();
	CommitmentScheme::commit(com_param, payload, &open).unwrap() == cm
}

/// Give a slice of the `payload`, and a hash function defined by the `hash_param`,
/// build a merkle tree, and output the root of the tree.
pub fn merkle_root(hash_param: HashParam, payload: &[[u8; 32]]) -> [u8; 32] {
	let tree = LedgerMerkleTree::new(hash_param, payload).unwrap();
	let root = tree.root();

	let mut bytes = [0u8; 32];
	root.serialize(bytes.as_mut()).unwrap();
	bytes
}
