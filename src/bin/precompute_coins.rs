// Copyright 2019-2022 Manta Network.
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

use anyhow::Result;
use indoc::indoc;
use manta_accounting::{
	asset::{Asset, AssetId},
	transfer::SpendingKey,
};
use manta_crypto::{
	accumulator::Accumulator,
	merkle_tree::full::FullMerkleTree,
	rand::{CryptoRng, Rand, RngCore, Sample},
};
use manta_pay::config::{
	FullParameters, KeyAgreementScheme, MerkleTreeConfiguration, Mint, MultiProvingContext,
	Parameters, PrivateTransfer, ProvingContext, Reclaim, UtxoCommitmentScheme, UtxoSetModel,
	VoidNumberHashFunction,
};
use manta_util::codec::{Decode, IoReader};
use pallet_manta_pay::types::TransferPost;
use rand::thread_rng;
use scale_codec::Encode;
use std::{
	env,
	fs::{self, File, OpenOptions},
	io::Write,
	path::{Path, PathBuf},
};

/// UTXO Set for Building Circuits
type UtxoSet = FullMerkleTree<MerkleTreeConfiguration>;

/// Loads parameters from the SDK, using `directory` as a temporary directory to store files.
#[inline]
fn load_parameters(directory: &Path) -> Result<(MultiProvingContext, Parameters, UtxoSetModel)> {
	println!("[INFO] Loading parameters ...");
	let mint_path = directory.join("mint.dat");
	manta_sdk::pay::testnet::proving::mint(&mint_path)?;
	println!("[INFO]     downloaded mint proving context");
	let private_transfer_path = directory.join("private-transfer.dat");
	manta_sdk::pay::testnet::proving::private_transfer(&private_transfer_path)?;
	println!("[INFO]     downloaded private-transfer proving context");
	let reclaim_path = directory.join("reclaim.dat");
	manta_sdk::pay::testnet::proving::reclaim(&reclaim_path)?;
	println!("[INFO]     downloaded reclaim proving context");
	let proving_context = MultiProvingContext {
		mint: ProvingContext::decode(IoReader(File::open(mint_path)?))
			.expect("Unable to decode MINT proving context."),
		private_transfer: ProvingContext::decode(IoReader(File::open(private_transfer_path)?))
			.expect("Unable to decode PRIVATE_TRANSFER proving context."),
		reclaim: ProvingContext::decode(IoReader(File::open(reclaim_path)?))
			.expect("Unable to decode RECLAIM proving context."),
	};
	println!("[INFO]     loaded multi-proving context");
	let parameters = Parameters {
		key_agreement: KeyAgreementScheme::decode(
			manta_sdk::pay::testnet::parameters::KEY_AGREEMENT,
		)
		.expect("Unable to decode KEY_AGREEMENT parameters."),
		utxo_commitment: UtxoCommitmentScheme::decode(
			manta_sdk::pay::testnet::parameters::UTXO_COMMITMENT_SCHEME,
		)
		.expect("Unable to decode UTXO_COMMITMENT_SCHEME parameters."),
		void_number_hash: VoidNumberHashFunction::decode(
			manta_sdk::pay::testnet::parameters::VOID_NUMBER_HASH_FUNCTION,
		)
		.expect("Unable to decode VOID_NUMBER_HASH_FUNCTION parameters."),
	};
	Ok((
		proving_context,
		parameters,
		UtxoSetModel::decode(manta_sdk::pay::testnet::parameters::UTXO_SET_PARAMETERS)
			.expect("Unable to decode UTXO_SET_PARAMETERS."),
	))
}

/// Samples a [`Mint`] transaction.
#[inline]
fn sample_mint<R>(
	proving_context: &ProvingContext,
	parameters: &Parameters,
	utxo_set_model: &UtxoSetModel,
	asset: Asset,
	rng: &mut R,
) -> TransferPost
where
	R: CryptoRng + RngCore + ?Sized,
{
	Mint::build(
		asset,
		SpendingKey::gen(rng).receiver(parameters, rng.gen(), asset),
	)
	.into_post(
		FullParameters::new(parameters, utxo_set_model),
		proving_context,
		rng,
	)
	.expect("Unable to build MINT proof.")
	.into()
}

/// Samples a [`PrivateTransfer`] transaction under two [`Mint`]s.
#[inline]
fn sample_private_transfer<R>(
	proving_context: &MultiProvingContext,
	parameters: &Parameters,
	utxo_set_model: &UtxoSetModel,
	asset_0: Asset,
	asset_1: Asset,
	rng: &mut R,
) -> ([TransferPost; 2], TransferPost)
where
	R: CryptoRng + RngCore + ?Sized,
{
	let mut utxo_set = UtxoSet::new(utxo_set_model.clone());

	let spending_key_0 = SpendingKey::gen(rng);
	let (receiver_0, pre_sender_0) = spending_key_0.internal_pair(parameters, rng.gen(), asset_0);

	let mint_0 = Mint::build(asset_0, receiver_0)
		.into_post(
			FullParameters::new(parameters, utxo_set.model()),
			&proving_context.mint,
			rng,
		)
		.expect("Unable to build MINT proof.");
	let sender_0 = pre_sender_0
		.insert_and_upgrade(&mut utxo_set)
		.expect("Just inserted so this should not fail.");

	let spending_key_1 = SpendingKey::gen(rng);
	let (receiver_1, pre_sender_1) = spending_key_1.internal_pair(parameters, rng.gen(), asset_1);

	let mint_1 = Mint::build(asset_1, receiver_1)
		.into_post(
			FullParameters::new(parameters, utxo_set.model()),
			&proving_context.mint,
			rng,
		)
		.expect("Unable to build MINT proof.");
	let sender_1 = pre_sender_1
		.insert_and_upgrade(&mut utxo_set)
		.expect("Just insterted so this should not fail.");

	let private_transfer = PrivateTransfer::build(
		[sender_0, sender_1],
		[
			spending_key_0.receiver(parameters, rng.gen(), asset_1),
			spending_key_1.receiver(parameters, rng.gen(), asset_0),
		],
	)
	.into_post(
		FullParameters::new(parameters, utxo_set.model()),
		&proving_context.private_transfer,
		rng,
	)
	.expect("Unable to build PRIVATE_TRANSFER proof.");

	([mint_0.into(), mint_1.into()], private_transfer.into())
}

/// Samples a [`Reclaim`] transaction under two [`Mint`]s.
#[inline]
fn sample_reclaim<R>(
	proving_context: &MultiProvingContext,
	parameters: &Parameters,
	utxo_set_model: &UtxoSetModel,
	asset_0: Asset,
	asset_1: Asset,
	rng: &mut R,
) -> ([TransferPost; 2], TransferPost)
where
	R: CryptoRng + RngCore + ?Sized,
{
	let mut utxo_set = UtxoSet::new(utxo_set_model.clone());

	let spending_key_0 = SpendingKey::new(rng.gen(), rng.gen());
	let (receiver_0, pre_sender_0) = spending_key_0.internal_pair(parameters, rng.gen(), asset_0);

	let mint_0 = Mint::build(asset_0, receiver_0)
		.into_post(
			FullParameters::new(parameters, utxo_set.model()),
			&proving_context.mint,
			rng,
		)
		.expect("Unable to build MINT proof.");
	pre_sender_0.insert_utxo(&mut utxo_set);
	let sender_0 = pre_sender_0
		.try_upgrade(&utxo_set)
		.expect("Just inserted so this should not fail.");

	let spending_key_1 = SpendingKey::new(rng.gen(), rng.gen());
	let (receiver_1, pre_sender_1) = spending_key_1.internal_pair(parameters, rng.gen(), asset_1);

	let mint_1 = Mint::build(asset_1, receiver_1)
		.into_post(
			FullParameters::new(parameters, utxo_set.model()),
			&proving_context.mint,
			rng,
		)
		.expect("Unable to build MINT proof.");
	pre_sender_1.insert_utxo(&mut utxo_set);
	let sender_1 = pre_sender_1
		.try_upgrade(&utxo_set)
		.expect("Just inserted so this should not fail.");

	let reclaim = Reclaim::build(
		[sender_0, sender_1],
		[spending_key_0.receiver(parameters, rng.gen(), asset_1)],
		asset_0,
	)
	.into_post(
		FullParameters::new(parameters, utxo_set.model()),
		&proving_context.private_transfer,
		rng,
	)
	.expect("Unable to build RECLAIM proof.");

	([mint_0.into(), mint_1.into()], reclaim.into())
}

/// Writes a new `const` definition to `$writer`.
macro_rules! write_const_array {
	($writer:ident, $name:ident, $value:expr) => {
		writeln!(
			$writer,
			"pub(crate) const {}: &[u8] = &{:?};\n",
			stringify!($name),
			$value.encode().as_slice()
		)
	};
}

/// Writes a new `const` definition to `$writer`.
macro_rules! write_const_nested_array {
	($writer:ident, $name:ident, $value:expr) => {
		writeln!(
			$writer,
			"pub(crate) const {}: &[&[u8]] = &[{}];\n",
			stringify!($name),
			$value
				.iter()
				.flat_map(|v| {
					format!("&{:?},", v.encode().as_slice())
						.chars()
						.collect::<Vec<_>>()
				})
				.collect::<String>(),
		)
	};
}

/// Builds sample transactions for testing.
#[inline]
fn main() -> Result<()> {
	let target_file = env::args()
		.nth(1)
		.map(PathBuf::from)
		.unwrap_or(env::current_dir()?.join("precomputed_coins.rs"));
	assert!(
		!target_file.exists(),
		"Specify a file to place the generated files: {:?}.",
		target_file,
	);
	fs::create_dir_all(
		&target_file
			.parent()
			.expect("This file should have a parent."),
	)?;

	let directory = tempfile::tempdir().expect("Unable to generate temporary test directory.");
	println!("[INFO] Temporary Directory: {:?}", directory);

	let mut rng = thread_rng();
	let (proving_context, parameters, utxo_set_model) = load_parameters(directory.path())?;

	let mint = sample_mint(
		&proving_context.mint,
		&parameters,
		&utxo_set_model,
		AssetId(0).value(100_000),
		&mut rng,
	);
	let (private_transfer_input, private_transfer) = sample_private_transfer(
		&proving_context,
		&parameters,
		&utxo_set_model,
		AssetId(0).value(10_000),
		AssetId(0).value(20_000),
		&mut rng,
	);
	let (reclaim_input, reclaim) = sample_reclaim(
		&proving_context,
		&parameters,
		&utxo_set_model,
		AssetId(0).value(10_000),
		AssetId(0).value(20_000),
		&mut rng,
	);

	let mut target_file = OpenOptions::new()
		.create_new(true)
		.write(true)
		.open(target_file)?;

	writeln!(
		target_file,
		indoc! {r"
		// Copyright 2019-2022 Manta Network.
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

		//! Precomputed Coins
		//!
		//! THIS FILE IS AUTOMATICALLY GENERATED by `src/bin/precompute_coins.rs`. DO NOT EDIT.
	"}
	)?;

	write_const_array!(target_file, MINT, mint)?;
	write_const_nested_array!(target_file, PRIVATE_TRANSFER_INPUT, private_transfer_input)?;
	write_const_array!(target_file, PRIVATE_TRANSFER, private_transfer)?;
	write_const_nested_array!(target_file, RECLAIM_INPUT, reclaim_input)?;
	write_const_array!(target_file, RECLAIM, reclaim)?;

	directory
		.close()
		.expect("Unable to delete temporary test directory.");

	Ok(())
}
