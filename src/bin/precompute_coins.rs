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
use async_std::{
	fs::{self, OpenOptions},
	io::WriteExt,
	path::{Path, PathBuf},
	println, task, writeln,
};
use indoc::indoc;
use manta_accounting::{
	asset::{Asset, AssetId},
	transfer::SpendingKey,
};
use manta_crypto::{
	accumulator::Accumulator,
	key::KeyAgreementScheme as _,
	merkle_tree::full::FullMerkleTree,
	rand::{CryptoRng, Rand, RngCore},
};
use manta_pay::config::{
	FullParameters, KeyAgreementScheme, MerkleTreeConfiguration, Mint, MultiProvingContext,
	Parameters, PrivateTransfer, ProvingContext, Receiver, Reclaim, UtxoCommitmentScheme,
	UtxoSetModel, VoidNumberHashFunction,
};
use manta_util::codec::Decode;
use pallet_manta_pay::types::TransferPost;
use rand::thread_rng;
use scale_codec::Encode;
use std::env;

///
type UtxoSet = FullMerkleTree<MerkleTreeConfiguration>;

///
#[inline]
async fn load_parameters(
	directory: &Path,
) -> Result<(MultiProvingContext, Parameters, UtxoSetModel)> {
	let mint_path = directory.join("mint.dat");
	manta_sdk::pay::testnet::proving::mint(&mint_path).await?;

	let private_transfer_path = directory.join("private-transfer.dat");
	manta_sdk::pay::testnet::proving::private_transfer(&private_transfer_path).await?;

	let reclaim_path = directory.join("reclaim.dat");
	manta_sdk::pay::testnet::proving::reclaim(&reclaim_path).await?;

	let proving_context = MultiProvingContext {
		mint: ProvingContext::decode(fs::read(mint_path).await?).expect(""),
		private_transfer: ProvingContext::decode(fs::read(private_transfer_path).await?).expect(""),
		reclaim: ProvingContext::decode(fs::read(reclaim_path).await?).expect(""),
	};

	let parameters = Parameters {
		key_agreement: KeyAgreementScheme::decode(
			manta_sdk::pay::testnet::parameters::KEY_AGREEMENT,
		)
		.expect(""),
		utxo_commitment: UtxoCommitmentScheme::decode(
			manta_sdk::pay::testnet::parameters::UTXO_COMMITMENT_SCHEME,
		)
		.expect(""),
		void_number_hash: VoidNumberHashFunction::decode(
			manta_sdk::pay::testnet::parameters::VOID_NUMBER_HASH_FUNCTION,
		)
		.expect(""),
	};

	Ok((
		proving_context,
		parameters,
		UtxoSetModel::decode(manta_sdk::pay::testnet::parameters::UTXO_SET_PARAMETERS).expect(""),
	))
}

///
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
		Receiver::new(
			parameters,
			rng.gen(),
			parameters.key_agreement.derive_owned(rng.gen()),
			parameters.key_agreement.derive_owned(rng.gen()),
			asset,
		),
	)
	.into_post(
		FullParameters::new(parameters, utxo_set_model),
		proving_context,
		rng,
	)
	.expect("")
	.into()
}

///
#[inline]
fn sample_private_transfer<R>(
	proving_context: &MultiProvingContext,
	parameters: &Parameters,
	utxo_set_model: &UtxoSetModel,
	asset_0: Asset,
	asset_1: Asset,
	rng: &mut R,
) -> [TransferPost; 3]
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
		.expect("");
	pre_sender_0.insert_utxo(&mut utxo_set);
	let sender_0 = pre_sender_0.try_upgrade(&utxo_set).expect("");

	let spending_key_1 = SpendingKey::new(rng.gen(), rng.gen());
	let (receiver_1, pre_sender_1) = spending_key_1.internal_pair(parameters, rng.gen(), asset_1);

	let mint_1 = Mint::build(asset_1, receiver_1)
		.into_post(
			FullParameters::new(parameters, utxo_set.model()),
			&proving_context.mint,
			rng,
		)
		.expect("");
	pre_sender_1.insert_utxo(&mut utxo_set);
	let sender_1 = pre_sender_1.try_upgrade(&utxo_set).expect("");

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
	.expect("");

	[mint_0.into(), mint_1.into(), private_transfer.into()]
}

///
#[inline]
fn sample_reclaim<R>(
	proving_context: &MultiProvingContext,
	parameters: &Parameters,
	utxo_set_model: &UtxoSetModel,
	asset_0: Asset,
	asset_1: Asset,
	rng: &mut R,
) -> [TransferPost; 3]
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
		.expect("");
	pre_sender_0.insert_utxo(&mut utxo_set);
	let sender_0 = pre_sender_0.try_upgrade(&utxo_set).expect("");

	let spending_key_1 = SpendingKey::new(rng.gen(), rng.gen());
	let (receiver_1, pre_sender_1) = spending_key_1.internal_pair(parameters, rng.gen(), asset_1);

	let mint_1 = Mint::build(asset_1, receiver_1)
		.into_post(
			FullParameters::new(parameters, utxo_set.model()),
			&proving_context.mint,
			rng,
		)
		.expect("");
	pre_sender_1.insert_utxo(&mut utxo_set);
	let sender_1 = pre_sender_1.try_upgrade(&utxo_set).expect("");

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
	.expect("");

	[mint_0.into(), mint_1.into(), reclaim.into()]
}

/// Writes a new `const` definition to `$writer`.
macro_rules! write_const {
	($writer:ident, $name:ident, $value:expr) => {
		writeln!(
			$writer,
			"pub(crate) const {}: &[u8] = &{:?};\n",
			stringify!($name),
			$value.encode().as_slice()
		)
	};
}

///
#[async_std::main]
#[inline]
async fn main() -> Result<()> {
	let target_file = env::args()
		.nth(1)
		.map(PathBuf::from)
		.unwrap_or(env::current_dir()?.join("precomputed_coins.rs").into());
	assert!(
		target_file.is_file().await || !target_file.exists().await,
		"Specify a file to place the generated files: {:?}.",
		target_file,
	);
	fs::create_dir_all(
		&target_file
			.parent()
			.expect("This file should have a parent."),
	)
	.await?;

	let directory = task::spawn_blocking(tempfile::tempdir)
		.await
		.expect("Unable to generate temporary test directory.");
	println!("[INFO] Temporary Directory: {:?}", directory).await;

	let mut rng = thread_rng();
	let (proving_context, parameters, utxo_set_model) =
		load_parameters(directory.path().into()).await?;

	let mint = sample_mint(
		&proving_context.mint,
		&parameters,
		&utxo_set_model,
		AssetId(0).value(100_000),
		&mut rng,
	);

	let private_transfer = sample_private_transfer(
		&proving_context,
		&parameters,
		&utxo_set_model,
		AssetId(0).value(10_000),
		AssetId(0).value(20_000),
		&mut rng,
	);

	let reclaim = sample_reclaim(
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
		.open(target_file)
		.await?;

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
	)
	.await?;

	write_const!(target_file, MINT, mint).await?;
	write_const!(target_file, PRIVATE_TRANSFER_INPUT_0, private_transfer[0]).await?;
	write_const!(target_file, PRIVATE_TRANSFER_INPUT_1, private_transfer[1]).await?;
	write_const!(target_file, PRIVATE_TRANSFER, private_transfer[2]).await?;
	write_const!(target_file, RECLAIM_INPUT_0, reclaim[0]).await?;
	write_const!(target_file, RECLAIM_INPUT_1, reclaim[1]).await?;
	write_const!(target_file, RECLAIM, reclaim[2]).await?;

	task::spawn_blocking(move || directory.close())
		.await
		.expect("Unable to delete temporary test directory.");

	Ok(())
}
