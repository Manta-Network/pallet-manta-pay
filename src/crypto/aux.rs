use crate::{ark_serialize::CanonicalSerialize, param::*};
use ark_crypto_primitives::{
	commitment::pedersen::Randomness, CommitmentScheme as ArkCommitmentScheme,
};
use ark_ed_on_bls12_381::Fr;
use ark_serialize::CanonicalDeserialize;

pub(crate) fn comm_open(
	com_param: &CommitmentParam,
	r: &[u8; 32],
	payload: &[u8],
	cm: &[u8; 32],
) -> bool {
	let open = Randomness(Fr::deserialize(r.as_ref()).unwrap());
	let cm = CommitmentOutput::deserialize(cm.as_ref()).unwrap();
	CommitmentScheme::commit(com_param, payload, &open).unwrap() == cm
}

pub fn merkle_root(hash_param: HashParam, payload: &[[u8; 32]]) -> [u8; 32] {
	let tree = LedgerMerkleTree::new(hash_param, payload).unwrap();
	let root = tree.root();

	let mut bytes = [0u8; 32];
	root.serialize(bytes.as_mut()).unwrap();
	bytes
}
