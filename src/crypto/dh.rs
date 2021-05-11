//! This file implements Diffie-Hellman Key Agreement for value encryption
//! TODO: maybe we should simply use ecies crate
//! <https://github.com/phayes/ecies-ed25519/>
use aes::{cipher::NewBlockCipher, Aes256, BlockDecrypt, BlockEncrypt};
use ark_std::rand::{CryptoRng, RngCore};
use generic_array::GenericArray;
use hkdf::Hkdf;
use sha2::Sha512Trunc256;
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
	let output = Hkdf::<Sha512Trunc256>::extract(Some(salt.as_ref()), input);
	let mut res = [0u8; 32];
	res.copy_from_slice(&output.0[0..32]);
	res
}
