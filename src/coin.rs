use crate::param::*;
use ark_crypto_primitives::{
	commitment::pedersen::Randomness,
	prf::{Blake2s, PRF},
	CommitmentScheme as ArkCommitmentScheme,
};
use ark_ed_on_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use ark_std::vec::Vec;
use frame_support::codec::{Decode, Encode};
use rand::{CryptoRng, RngCore};

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
		crate::crypto::comm_open(&param, &self.s, &payload, &self.cm)
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

/// A MantaCoin is a commitment `cm = com(v||k, s)`.
#[derive(Encode, Debug, Decode, Clone, Default, PartialEq)]
pub struct MantaCoin {
	pub cm_bytes: [u8; 32],
}

/// Information related to a coin that may be revealed.
#[derive(Encode, Decode, Default, Clone, PartialEq)]
pub struct MantaCoinPubInfo {
	pub pk: [u8; 32],
	pub rho: [u8; 32],
	pub s: [u8; 32],
	pub r: [u8; 32],
	pub k: [u8; 32],
}

/// Information related to a coin that may __not__ be revealed,
/// unless the coin is spend.
#[derive(Encode, Decode, Default, Clone, PartialEq)]
pub struct MantaCoinPrivInfo {
	pub value: u64,
	pub sk: [u8; 32],
	pub sn: [u8; 32],
}

/// Make a coin from inputs.
#[allow(dead_code)]
pub fn make_coin<R: RngCore + CryptoRng>(
	commit_param: &CommitmentParam,
	sk: [u8; 32],
	value: u64,
	rng: &mut R,
) -> (MantaCoin, MantaCoinPubInfo, MantaCoinPrivInfo) {
	//  sample a random rho
	let mut rho = [0u8; 32];
	rng.fill_bytes(&mut rho);

	// pk = PRF(sk, 0); which is also the address
	let pk = <Blake2s as PRF>::evaluate(&sk, &[0u8; 32]).unwrap();

	// sn = PRF(sk, rho)
	let sn = <Blake2s as PRF>::evaluate(&sk, &rho).unwrap();

	// k = com(pk||rho, r)
	let buf = [pk, rho].concat();

	let r = Fr::rand(rng);
	let mut r_bytes = [0u8; 32];
	r.serialize(r_bytes.as_mut()).unwrap();
	let r = Randomness(r);

	let k = CommitmentScheme::commit(&commit_param, &buf, &r).unwrap();
	let mut k_bytes = [0u8; 32];
	k.serialize(k_bytes.as_mut()).unwrap();

	// cm = com(v||k, s)
	let buf: Vec<u8> = [value.to_le_bytes().as_ref(), k_bytes.clone().as_ref()].concat();

	let s = Fr::rand(rng);
	let mut s_bytes = [0u8; 32];
	s.serialize(s_bytes.as_mut()).unwrap();
	let s = Randomness(s);

	let cm = CommitmentScheme::commit(&commit_param, &buf, &s).unwrap();
	let mut cm_bytes = [0u8; 32];
	cm.serialize(cm_bytes.as_mut()).unwrap();

	let coin = MantaCoin { cm_bytes };
	let pub_info = MantaCoinPubInfo {
		pk,
		rho,
		s: s_bytes,
		r: r_bytes,
		k: k_bytes,
	};
	let priv_info = MantaCoinPrivInfo { value, sk, sn };
	(coin, pub_info, priv_info)
}
