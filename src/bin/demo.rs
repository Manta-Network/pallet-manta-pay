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

use ark_serialize::CanonicalDeserialize;
use data_encoding::BASE64;
use manta_asset::{MantaAsset, MantaAssetFullReceiver, Process, Sampling, TEST_ASSET};
use manta_crypto::{
	CommitmentParam, Groth16Pk, HashParam, MantaZKPVerifier, COMMIT_PARAM, HASH_PARAM,
};
use pallet_manta_pay::{
	generate_mint_payload, generate_private_transfer_payload, generate_reclaim_payload,
	LedgerSharding, MantaSerDes, PrivateTransferData, ReclaimData, SenderMetaData, Shards,
	RECLAIM_PK, TRANSFER_PK,
};
use rand_chacha::{
	rand_core::{RngCore, SeedableRng},
	ChaCha20Rng,
};
use std::{
	fs::File,
	io::{Read, Write},
};

fn main() {
	let commit_param = CommitmentParam::deserialize(COMMIT_PARAM.data);
	let hash_param = HashParam::deserialize(HASH_PARAM.data);
	let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
	let mut sk = [0u8; 32];

	// load the ZKP keys
	let mut file = File::open("transfer_pk.bin").unwrap();
	let mut transfer_key_bytes: Vec<u8> = vec![];
	file.read_to_end(&mut transfer_key_bytes).unwrap();
	let buf: &[u8] = transfer_key_bytes.as_ref();
	let transfer_pk = Groth16Pk::deserialize_unchecked(buf).unwrap();

	let transfer_vk = TRANSFER_PK;

	let mut file = File::open("reclaim_pk.bin").unwrap();
	let mut reclaim_key_bytes: Vec<u8> = vec![];
	file.read_to_end(&mut reclaim_key_bytes).unwrap();
	let buf: &[u8] = reclaim_key_bytes.as_ref();
	let reclaim_pk = Groth16Pk::deserialize_unchecked(buf).unwrap();

	let reclaim_vk = RECLAIM_PK;

	// build sender
	let mut assets = Vec::new();
	let mut senders = Vec::new();
	let mut shards = Shards::default();
	for i in 1..=4 {
		// generate the i-th minting data
		rng.fill_bytes(&mut sk);
		let asset = MantaAsset::sample(&commit_param, &sk, &TEST_ASSET, &10, &mut rng);
		let payload = generate_mint_payload(&asset);
		let data = BASE64.encode(&payload);

		let mut file = File::create(format!("token_{}.utxo", i)).unwrap();
		file.write_all(data.as_ref()).unwrap();

		let mut file = File::create(format!("token_{}.hex", i)).unwrap();
		file.write_all(formating(payload.to_vec()).as_ref())
			.unwrap();

		shards.update(&asset.commitment, hash_param.clone());

		let sender = SenderMetaData::build(
			hash_param.clone(),
			asset.clone(),
			&shards.shard[asset.commitment[0] as usize].list,
		);

		senders.push(sender);
		assets.push(asset);
	}

	// build receivers
	let mut receivers_full = Vec::new();
	let mut receivers_processed = Vec::new();
	for _i in 1..4 {
		let receiver_full =
			MantaAssetFullReceiver::sample(&commit_param, &sk, &TEST_ASSET, &(), &mut rng);
		let receiver = receiver_full.prepared.process(&10, &mut rng);
		receivers_full.push(receiver_full);
		receivers_processed.push(receiver);
	}
	let mut buf1 = vec![];
	let mut buf2 = vec![];
	receivers_processed[0].serialize(&mut buf1);
	receivers_processed[1].serialize(&mut buf2);
	println!("receiver 1 {:?}", buf1);
	println!("receiver 2 {:?}", buf2);

	// make the transfer payload
	let payload = generate_private_transfer_payload(
		commit_param.clone(),
		hash_param.clone(),
		&transfer_pk,
		senders[0].clone(),
		senders[1].clone(),
		receivers_processed[0].clone(),
		receivers_processed[1].clone(),
		&mut rng,
	);

	let data = BASE64.encode(&payload);
	let mut file = File::create("private_transfer.payload").unwrap();
	file.write_all(data.as_ref()).unwrap();

	let mut file = File::create("private_transfer.hex").unwrap();
	file.write_all(formating(payload.to_vec()).as_ref())
		.unwrap();

	// sanity checks
	let transfer_data = PrivateTransferData::deserialize(payload.as_ref());
	assert!(transfer_data.verify(&transfer_vk));

	shards.update(&receivers_processed[0].commitment, hash_param.clone());
	shards.update(&receivers_processed[1].commitment, hash_param.clone());

	// make the reclaim payload

	let payload = generate_reclaim_payload(
		commit_param,
		hash_param,
		&reclaim_pk,
		senders[2].clone(),
		senders[3].clone(),
		receivers_processed[2].clone(),
		10,
		&mut rng,
	);

	let data = BASE64.encode(&payload);
	let mut file = File::create("reclaim.payload").unwrap();
	file.write_all(data.as_ref()).unwrap();

	let mut file = File::create("reclaim.hex").unwrap();
	file.write_all(formating(payload.to_vec()).as_ref())
		.unwrap();

	// sanity checks
	let reclaim_data = ReclaimData::deserialize(payload.as_ref());
	assert!(reclaim_data.verify(&reclaim_vk));
}

// converting a vector of u8 into a string of Hex numbers
// with a prefix of 0x
fn formating(input: Vec<u8>) -> String {
	let mut res = "0x".to_string();
	for e in input {
		res = [res, format! {"{:02x}", e}].concat();
	}
	res
}
