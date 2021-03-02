use crate::manta_token::MantaCoin;
use crate::param::*;
use crate::serdes::*;
use ark_crypto_primitives::{commitment::pedersen::Randomness, CommitmentScheme};
use ark_ed_on_bls12_381::{Fq, Fr};
use ark_ff::ToConstraintField;
use ark_groth16::verify_proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use blake2::{Blake2s, Digest};

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

#[allow(dead_code)]
pub fn comm_open(
    com_param: &MantaCoinCommitmentParam,
    r: &[u8; 32],
    payload: &[u8],
    cm: &[u8; 32],
) -> bool {
    let open = Randomness(Fr::deserialize(r.as_ref()).unwrap());
    let cm = MantaCoinCommitmentOutput::deserialize(cm.as_ref()).unwrap();
    MantaCoinCommitmentScheme::commit(com_param, payload, &open).unwrap() == cm
}

#[allow(dead_code)]
pub fn merkle_root(hash_param: HashParam, payload: &[MantaCoin]) -> [u8; 32] {
    let leaf: Vec<[u8; 32]> = payload.iter().map(|x| (x.cm_bytes.clone())).collect();
    let tree = LedgerMerkleTree::new(hash_param, &leaf).unwrap();
    let root = tree.root();

    let mut bytes = [0u8; 32];
    root.serialize(bytes.as_mut()).unwrap();
    bytes
}

pub fn manta_verify_transfer_zkp(
    transfer_key_bytes: Vec<u8>,
    proof: [u8; 192],
    sn_old: [u8; 32],
    k_old: [u8; 32],
    k_new: [u8; 32],
    cm_new: [u8; 32],
    merkle_root: [u8; 32],
) -> bool {
    let vk = Groth16VK::deserialize(transfer_key_bytes.as_ref()).unwrap();
    let pvk = Groth16PVK::from(vk);
    let proof = Groth16Proof::deserialize(proof.as_ref()).unwrap();
    let k_old = MantaCoinCommitmentOutput::deserialize(k_old.as_ref()).unwrap();
    let k_new = MantaCoinCommitmentOutput::deserialize(k_new.as_ref()).unwrap();
    let cm_new = MantaCoinCommitmentOutput::deserialize(cm_new.as_ref()).unwrap();
    let merkle_root = HashOutput::deserialize(merkle_root.as_ref()).unwrap();

    let mut inputs = [k_old.x, k_old.y, k_new.x, k_new.y, cm_new.x, cm_new.y].to_vec();
    let sn: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(sn_old.as_ref()).unwrap();
    let mr: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&merkle_root).unwrap();
    inputs = [inputs[..].as_ref(), sn.as_ref(), mr.as_ref()].concat();

    verify_proof(&pvk, &proof, &inputs[..]).unwrap()
}

pub fn manta_verify_forfeit_zkp(
    forfeit_key_bytes: Vec<u8>,
    value: u64,
    proof: [u8; 192],
    sn_old: [u8; 32],
    k_old: [u8; 32],
    merkle_root: [u8; 32],
) -> bool {
    let vk = Groth16VK::deserialize(forfeit_key_bytes.as_ref()).unwrap();
    let pvk = Groth16PVK::from(vk);
    let proof = Groth16Proof::deserialize(proof.as_ref()).unwrap();
    let k_old = MantaCoinCommitmentOutput::deserialize(k_old.as_ref()).unwrap();
    let merkle_root = HashOutput::deserialize(merkle_root.as_ref()).unwrap();

    let mut inputs = [k_old.x, k_old.y].to_vec();
    let sn: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(sn_old.as_ref()).unwrap();
    let mr: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&merkle_root).unwrap();
    let value_fq = Fq::from(value);
    inputs = [
        inputs[..].as_ref(),
        sn.as_ref(),
        mr.as_ref(),
        [value_fq].as_ref(),
    ]
    .concat();

    verify_proof(&pvk, &proof, &inputs[..]).unwrap()
}
