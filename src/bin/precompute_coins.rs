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

use indoc::indoc;
use manta_api::{
	generate_mint_struct, generate_private_transfer_struct, generate_reclaim_struct,
	util::into_array_unchecked,
	zkp::{
		keys::{reclaim, transfer},
		sample::*,
	},
};
use manta_asset::{shard_index, TEST_ASSET, UTXO};
use manta_crypto::{
	commitment_parameters, leaf_parameters, two_to_one_parameters, Groth16Pk, MantaSerDes,
};
use manta_data::{
	BuildMetadata, MintData, MintPayload, PrivateTransferPayload, ReclaimPayload,
	MINT_PAYLOAD_SIZE, PRIVATE_TRANSFER_PAYLOAD_SIZE, RECLAIM_PAYLOAD_SIZE,
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::{collections::HashMap, fs::File, io::Read, sync::Once};

/// Insert utxo to the commitment set
fn insert_utxo(utxo: &UTXO, commitment_set: &mut HashMap<u8, Vec<[u8; 32]>>) {
	let shard_index = shard_index(*utxo);
	let shard = commitment_set.entry(shard_index).or_default();
	shard.push(utxo.clone());
}

/// Generate a precomputed coins
/// * coin_1: a private coin with TEST_ASSET and value 89757
/// * coin_2: a private coin with TEST_ASSET and value 89758
/// * transfer_data: [coin_1, coin_2] -> [coin_3: (TEST_ASSET, 100000), coin_4, (TEST_ASSET, 79515)]
/// * reclaim_data: [coin_1, coin_2] -> [coin_3: (TEST_ASSET, 100000), coin_4_public, (TEST_ASSET, 79515)]
fn precompute_coins() -> (
	MintPayload,
	MintPayload,
	PrivateTransferPayload,
	ReclaimPayload,
) {
	// setup parameters
	let (commit_params, leaf_params, two_to_one_params) = (
		commitment_parameters(),
		leaf_parameters(),
		two_to_one_parameters(),
	);

	let mut rng = ChaCha20Rng::from_seed([55u8; 32]);
	let mut ledger = HashMap::new();

	// generate a coin with id TEST_ASSET and value 89757
	let sender_1 = fixed_asset(&commit_params, &TEST_ASSET, &89_757, &mut rng);
	let coin_1 = generate_mint_struct(&sender_1);
	let mut coin_1_bytes = Vec::new();
	coin_1.serialize(&mut coin_1_bytes).unwrap();

	// generate a coin with id TEST_ASSET and value 89758
	let sender_2 = fixed_asset(&commit_params, &TEST_ASSET, &89_758, &mut rng);
	let coin_2 = generate_mint_struct(&sender_2);
	let mut coin_2_bytes = Vec::new();
	coin_2.serialize(&mut coin_2_bytes).unwrap();

	// transfer sender_1 and sender_2 to two receivers
	insert_utxo(&sender_1.utxo, &mut ledger);
	insert_utxo(&sender_2.utxo, &mut ledger);
	let sender_1_meta = sender_1
		.build(
			&leaf_params,
			&two_to_one_params,
			ledger.get(&shard_index(sender_1.utxo)).unwrap(),
		)
		.unwrap();
	let sender_2_meta = sender_2
		.build(
			&leaf_params,
			&two_to_one_params,
			ledger.get(&shard_index(sender_2.utxo)).unwrap(),
		)
		.unwrap();

	let receiver_1 = fixed_receiver(&commit_params, &TEST_ASSET, &100_000, &mut rng);
	let receiver_2 = fixed_receiver(&commit_params, &TEST_ASSET, &79_515, &mut rng);
	let mut transfer_bytes = Vec::new();
	let transfer_data = generate_private_transfer_struct(
		commit_params.clone(),
		leaf_params.clone(),
		two_to_one_params.clone(),
		&transfer().unwrap().0,
		[sender_1_meta.clone(), sender_2_meta.clone()],
		[receiver_1, receiver_2],
		&mut rng,
	)
	.unwrap();
	transfer_data.serialize(&mut transfer_bytes).unwrap();

	// reclaim 79515 TEST_ASSET, 10000 transferred to a coin
	let receiver = fixed_receiver(&commit_params, &TEST_ASSET, &100_000, &mut rng);
	let reclaim_data = generate_reclaim_struct(
		commit_params,
		leaf_params,
		two_to_one_params,
		&reclaim().unwrap().0,
		[sender_1_meta, sender_2_meta],
		receiver,
		79_515,
		&mut rng,
	)
	.unwrap();
	let mut reclaim_bytes = Vec::new();
	reclaim_data.serialize(&mut reclaim_bytes).unwrap();
	(
		into_array_unchecked(coin_1_bytes),
		into_array_unchecked(coin_2_bytes),
		into_array_unchecked(transfer_bytes),
		into_array_unchecked(reclaim_bytes),
	)
}

/// Writes a new `const` definition to `$writer`.
macro_rules! print_const {
	($var:ident) => {
		println!(
			"pub(crate) const {}: &[u8] = &{:?};\n",
			stringify!($var),
			$var
		)
	};
}

#[allow(non_snake_case)]
fn main() {
	let (COIN_1, COIN_2, TRANSFER_DATA, RECLAIM_DATA) = precompute_coins();
	let license_doc_string = indoc! {"// Copyright 2019-2021 Manta Network.
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
	// along with pallet-manta-pay.  If not, see <http://www.gnu.org/licenses/>."};
	println!("{}\n", license_doc_string);
	print_const!(COIN_1);
	print_const!(COIN_2);
	print_const!(TRANSFER_DATA);
	print_const!(RECLAIM_DATA);
}
