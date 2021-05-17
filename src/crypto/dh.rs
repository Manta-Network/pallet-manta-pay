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

//! This file implements Diffie-Hellman Key Agreement for value encryption
//! TODO: maybe we should simply use ecies crate
//! <https://github.com/phayes/ecies-ed25519/>
use aes::{cipher::NewBlockCipher, Aes256, BlockDecrypt, BlockEncrypt};
use ark_std::rand::{CryptoRng, RngCore};
use generic_array::GenericArray;
use blake2::{Blake2s, Digest};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// Encrypt the value under receiver's public key.
///
/// # <weight>
/// Steps:
///     1. sample a random, ephemeral field element: sender_x
///     2. compute the group element sender_pk
///     3. compute the shared secret ss = receiver_pk^x
///     4. set aes_key = KDF("manta kdf instantiated with Sha512-256 hash function" | ss)
///     5. compute c = aes_enc(value.to_le_bytes(), aes_key)
///     6. return (sender_pk, c)
/// # </weight>
#[allow(dead_code)]
pub fn manta_dh_enc<R: RngCore + CryptoRng>(
	receiver_pk_bytes: &[u8; 32],
	value: u64,
	rng: &mut R,
) -> ([u8; 32], [u8; 16]) {
	let sender_sk = EphemeralSecret::new(rng);
	let sender_pk = PublicKey::from(&sender_sk);

	let receiver_pk = PublicKey::from(*receiver_pk_bytes);
	let shared_secret = sender_sk.diffie_hellman(&receiver_pk);
	let ss = manta_kdf(&shared_secret.to_bytes());
	let aes_key = GenericArray::from_slice(&ss);

	let msg = [value.to_le_bytes().as_ref(), [0u8; 8].as_ref()].concat();
	assert_eq!(msg.len(), 16);
	let mut block = GenericArray::clone_from_slice(&msg);
	let cipher = Aes256::new(&aes_key);
	cipher.encrypt_block(&mut block);

	let mut res = [0u8; 16];
	res.copy_from_slice(block.as_slice());

	(sender_pk.to_bytes(), res)
}

/// Decrypt the value under receiver's public key.
///
/// # <weight>
/// Steps:
///     1. compute the shared secret ss = sender_pk^receiver_sk
///     2. set aes_key = KDF("manta kdf instantiated with Sha512-256 hash function" | ss)
///     3. compute m = aes_dec(cipher, aes_key)
///     4. return m as u64
/// # </weight>
#[allow(dead_code)]
pub fn manta_dh_dec(
	cipher: &[u8; 16],
	sender_pk_bytes: &[u8; 32],
	receiver_sk_bytes: &[u8; 32],
) -> u64 {
	let receiver_sk = StaticSecret::from(*receiver_sk_bytes);
	let sender_pk = PublicKey::from(*sender_pk_bytes);
	let shared_secret = receiver_sk.diffie_hellman(&sender_pk);
	let ss = manta_kdf(&shared_secret.to_bytes());
	let aes_key = GenericArray::from_slice(&ss);
	let mut block = *cipher;
	let mut block = GenericArray::from_mut_slice(&mut block);
	let cipher = Aes256::new(&aes_key);
	cipher.decrypt_block(&mut block);

	(block[0] as u64)
		+ ((block[1] as u64) << 8)
		+ ((block[2] as u64) << 16)
		+ ((block[3] as u64) << 24)
		+ ((block[4] as u64) << 32)
		+ ((block[5] as u64) << 40)
		+ ((block[6] as u64) << 48)
		+ ((block[7] as u64) << 56)
}

#[allow(dead_code)]
// this function is a wrapper of hkdf-sha512: m = hkdf-extract(salt, seed)
// with a fixed salt
fn manta_kdf(input: &[u8]) -> [u8; 32] {
	let salt = "manta kdf instantiated with Sha512-256 hash function";
	let mut hasher = Blake2s::new();
	hasher.update([input, salt.as_bytes()].concat());
	let digest = hasher.finalize();
	let mut res = [0u8; 32];
	res.copy_from_slice(digest.as_slice());
	res
}
