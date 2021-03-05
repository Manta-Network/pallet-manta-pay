use crate::param::*;
use ark_crypto_primitives::{
	commitment::pedersen::Randomness,
	prf::{Blake2s, PRF},
	CommitmentScheme,
};
use ark_ed_on_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use ark_std::vec::Vec;
use frame_support::codec::{Decode, Encode};
use rand_core::{CryptoRng, RngCore};

/// a MantaCoin is a pair of commitment cm, where
///  * cm = com(v||k, s), commits to the value, and
#[derive(Encode, Debug, Decode, Clone, Default, PartialEq)]
pub struct MantaCoin {
	pub cm_bytes: [u8; 32],
}

#[derive(Encode, Decode, Default, Clone, PartialEq)]
pub struct MantaCoinPubInfo {
	pub pk: [u8; 32],
	pub rho: [u8; 32],
	pub s: [u8; 32],
	pub r: [u8; 32],
	pub k: [u8; 32],
}

#[derive(Encode, Decode, Default, Clone, PartialEq)]
pub struct MantaCoinPrivInfo {
	pub value: u64,
	pub sk: [u8; 32],
	pub sn: [u8; 32],
}

/// make a coin from inputs
#[allow(dead_code)]
pub fn make_coin<R: RngCore + CryptoRng>(
	commit_param: &MantaCoinCommitmentParam,
	sk: [u8; 32],
	value: u64,
	rng: &mut R,
) -> (MantaCoin, MantaCoinPubInfo, MantaCoinPrivInfo) {
	// rebuild the parameters from the inputs
	// let mut com_rng = ChaCha20Rng::from_seed(*commit_param_seed);
	// let commit_param = MantaCoinCommitmentScheme::setup(&mut com_rng).unwrap();

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

	let k = MantaCoinCommitmentScheme::commit(&commit_param, &buf, &r).unwrap();
	let mut k_bytes = [0u8; 32];
	k.serialize(k_bytes.as_mut()).unwrap();

	// cm = com(v||k, s)
	let buf: Vec<u8> = [value.to_le_bytes().as_ref(), k_bytes.clone().as_ref()].concat();

	let s = Fr::rand(rng);
	let mut s_bytes = [0u8; 32];
	s.serialize(s_bytes.as_mut()).unwrap();
	let s = Randomness(s);

	let cm = MantaCoinCommitmentScheme::commit(&commit_param, &buf, &s).unwrap();
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
	let priv_info = MantaCoinPrivInfo { sk, sn, value };
	(coin, pub_info, priv_info)
}
