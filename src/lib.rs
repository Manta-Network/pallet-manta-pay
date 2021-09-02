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

//! # Manta pay Module
//!
//! A simple, secure module for manta pay: an anonymous transfer protocol
//!
//! ## Overview
//!
//! The Assets module provides functionality for asset management of fungible asset classes
//! with a fixed supply, including:
//!
//! * Asset Issuance
//! * Asset Transfer
//! * Private Asset Mint
//! * Private Asset Transfer
//! * Private Asset Reclaim
//!
//! To use it in your runtime, you need to implement the assets [`Config`](./config.Config.html).
//!
//! The supported dispatchable functions are documented in the [`Call`](./enum.Call.html) enum.
//!
//! ### Terminology
//!
//! * **Asset issuance:** The creation of the asset (note: this asset can only be created once)
//! * **Asset transfer:** The action of transferring assets from one account to another.
//! * **Private asset mint:** The action of converting certain number of `Asset`s into an UTXO
//! that holds same number of private assets.
//! * **Private asset transfer:** The action of transferring certain number of private assets from
//! two UTXOs to another two UTXOs.
//! * **Private asset reclaim:** The action of transferring certain number of private assets from
//! two UTXOs to another UTXO, and converting the remaining private assets back to public
//! assets.
//!
//! The assets system in Manta is designed to make the following possible:
//!
//! * Issue a public asset to its creator's account.
//! * Move public assets between accounts.
//! * Converting public assets to private assets, and vice versa.
//! * Move private assets between accounts (in UTXO model).
//!
//! ## Interface
//!
//! ### Dispatchable Functions
//!
//! * `init_asset` - Issues the total supply of a new fungible asset to the account of the caller of the function.
//! * `transfer_asset` - Transfers an `amount` of units of fungible asset `id` from the balance of
//! the function caller's account (`origin`) to a `target` account.
//! * `mint_private_asset` - Converting an `amount` of units of fungible asset `id` from the caller to a private UTXO.
//! (The caller does not need to be the owner of this UTXO)
//! * `private_transfer` - Transfer two input UTXOs into two output UTXOs. Require that 1) the input UTXOs are
//! already in the ledger and are not spend before 2) the sum of private assets in input UTXOs matches that
//! of the output UTXOs. The requirements are guaranteed via ZK proof.
//! * `reclaim` - Transfer two input UTXOs into one output UTXOs, and convert the remaining assets to the
//! public assets. Require that 1) the input UTXOs are already in the ledger and are not spend before; 2) the
//! sum of private assets in input UTXOs matches that of the output UTXO + the reclaimed amount. The
//! requirements are guaranteed via ZK proof.
//!
//! Please refer to the [`Call`](./enum.Call.html) enum and its associated variants for documentation on each
//! function.
//!
//! ### Public Functions
//! <!-- Original author of descriptions: @gavofyork -->
//!
//! * `balance`      - Get the asset balance of `who`.
//! * `total_supply` - Get the total supply of an asset `id`.
//! * `pool_balance` - Get the total number of private asset.
//!
//! Please refer to the [`Module`](./struct.Module.html) struct for details on publicly available functions.
//!
//! ## Usage
//!
//! The following example shows how to use the Assets module in your runtime by exposing public functions to:
//!
//! * Initiate the fungible asset for a token distribution event (airdrop).
//! * Query the fungible asset holding balance of an account.
//! * Query the total supply of a fungible asset that has been issued.
//! * Query the total number of private fungible asset that has been minted and not reclaimed.
//!
//! ### Prerequisites
//!
//! Import the Assets module and types and derive your runtime's configuration traits from the Assets module trait.
//!
//! ## Related Modules
//!
//! * [`System`](../frame_system/index.html)
//! * [`Support`](../frame_support/index.html)

// Ensure we're `no_std` when compiling for Wasm.
// #![cfg_attr(not(feature = "std"), no_std)]
#![no_std]

#[cfg(feature = "runtime-benchmarks")]
mod runtime_benchmark;

#[cfg(test)]
mod test;
#[cfg(test)]
#[macro_use]
extern crate std;

pub use manta_crypto::MantaSerDes;
pub mod weights;
pub use weights::WeightInfo;
pub mod precomputed_coins;

use ark_std::vec::Vec;
use frame_support::{decl_error, decl_event, decl_module, decl_storage, ensure};
use frame_system::ensure_signed;
use manta_asset::{AssetBalance, AssetId, MantaRandomValue, SanityCheck};
use manta_crypto::*;
use manta_data::*;
use manta_ledger::{LedgerSharding, MantaPrivateAssetLedger};
use sp_runtime::{
	traits::{StaticLookup, Zero},
	DispatchError,
};
use sp_std::prelude::*;

/// An abstract struct for manta-pay.
pub struct MantaPay;

/// The module configuration trait.
pub trait Config: frame_system::Config {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Config>::Event>;

	/// Weight information for extrinsics in this pallet.
	type WeightInfo: WeightInfo;
}

decl_module! {
	pub struct Module<T: Config> for enum Call where origin: T::Origin {
		type Error = Error<T>;

		fn deposit_event() = default;

		/// Issue a new class of fungible assets. There are, and will only ever be, `total`
		/// such assets and they'll all belong to the `origin` initially. It will have an
		/// identifier `AssetId` instance: this will be specified in the `Issued` event.
		/// # <weight>
		/// - `O(1)`
		/// - 1 storage mutation (codec `O(1)`).
		/// - 2 storage writes (codec `O(1)`).
		/// - 1 event.
		/// # </weight>
		#[weight = T::WeightInfo::init_asset()]
		fn init_asset(
			origin,
			asset_id: AssetId,
			total: AssetBalance
		) {
			// Checks that the asset has been initialized.
			ensure!(!TotalSupply::contains_key(&asset_id), Error::<T>::AlreadyInitialized);

			// Checks that the origin is valid.
			let origin = ensure_signed(origin)?;

			// NOTE: For now we hard code the parameters generated from the following seeds:
			//  * leaf hash parameter seed: ???
			//  * two-to-one hash parameter seed: ???
			//  * commitment parameter seed: [2u8; 32]
			// In the future, we may want to pass them in to `init_asst` or generate them here.

			// Loads leaf parameters and computes checksum.
			let leaf_params = try_leaf_parameters()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to init the asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;
			let leaf_param_checksum = leaf_params.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to init the asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;

			// Loads two-to-one parameters and computes checksum.
			let two_to_one_params = try_two_to_one_parameters()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to init the asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;
			let two_to_one_param_checksum = two_to_one_params.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to init the asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;

			// Loads commitment parameters and computes checksum.
			let commit_params = try_commitment_parameters()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to init the asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;
			let commit_param_checksum = commit_params.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to init the asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;

			// SAFETY NOTE: For the current prototype, we compute ZKP proving/verifying keys
			// off-chain. For complete security, we need to implement a multi-party computation
			// to generate these keys. See the ZKP source for more details.

			// Loads ZKP proving/verifying keys and computes checksum.
			let transfer_key_digest = TRANSFER_VK.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to init the asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;
			let reclaim_key_digest = RECLAIM_VK.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to init the asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;

			// Saves checksums to storage.
			LeafHashParamChecksum::put(leaf_param_checksum);
			TwoToOneHashParamChecksum::put(two_to_one_param_checksum);
			CommitParamChecksum::put(commit_param_checksum);
			PrivateTransferKeyChecksum::put(transfer_key_digest);
			ReclaimKeyChecksum::put(reclaim_key_digest);

			// Initializes public/private asset supply and credits assets to origin.
			PoolBalance::insert(asset_id, 0);
			TotalSupply::insert(asset_id, total);
			Balances::<T>::insert(&origin, asset_id, total);

			// Builds a new UTXO set, void number set, and encrypted asset set.
			CoinShards::put(MantaPrivateAssetLedger::default());
			VNList::put(Vec::<[u8; 32]>::new());
			EncryptedAssetList::put(Vec::<MantaEciesCiphertext>::new());

			// Deposits event.
			Self::deposit_event(RawEvent::Issued(origin, asset_id, total));
		}

		/// Move some assets from one holder to another.
		///
		/// # <weight>
		/// - `O(1)`
		/// - 1 static lookup
		/// - 2 storage mutations (codec `O(1)`).
		/// - 1 event.
		/// # </weight>
		#[weight = T::WeightInfo::transfer_asset()]
		fn transfer_asset(
			origin,
			target: <T::Lookup as StaticLookup>::Source,
			asset_id: AssetId,
			value: AssetBalance
		) {
			// Checks that the asset has been initialized.
			ensure!(TotalSupply::contains_key(&asset_id), Error::<T>::BasecoinNotInit);

			// Checks that the transfer amount is not zero.
			ensure!(!value.is_zero(), Error::<T>::AmountZero);

			// Checks that the origin and target account exist and are valid.
			let origin = ensure_signed(origin)?;
			let target = T::Lookup::lookup(target)?;

			// Checks that the origin balance is large enough to be able to withdraw `value`.
			ensure!(Balances::<T>::get(&origin, asset_id) >= value, Error::<T>::BalanceLow);

			// Updates balances.
			Balances::<T>::mutate(&origin, asset_id, |balance| *balance -= value);
			Balances::<T>::mutate(&target, asset_id, |balance| *balance += value);

			// Deposits event.
			Self::deposit_event(RawEvent::Transferred(origin, target, asset_id, value));
		}

		/// Given an amount, and relevant data, mint the token to the ledger
		#[weight = T::WeightInfo::mint_private_asset()]
		fn mint_private_asset(
			origin,
			data: MintData
		) {
			// Checks that the asset has been initialized.
			ensure!(TotalSupply::contains_key(&data.asset_id), Error::<T>::BasecoinNotInit);

			let origin = ensure_signed(origin)?;

			// Checks that the origin balance is large enough to be able to withdraw `value`.
			ensure!(
				Balances::<T>::get(&origin, data.asset_id) >= data.value,
				Error::<T>::BalanceLow
			);

			// Ensures the local leaf parameters have the matching checksum.
			let leaf_param_checksum_local = HASH_PARAM.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to mint the asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;
			ensure!(
				leaf_param_checksum_local == LeafHashParamChecksum::get(),
				Error::<T>::ParamFail
			);
			let leaf_params = try_leaf_parameters()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to mint the asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;

			// Ensures the local two-to-one parameters have the matching checksum.
			let two_to_one_param_checksum_local = HASH_PARAM.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to mint the asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;
			ensure!(
				two_to_one_param_checksum_local == TwoToOneHashParamChecksum::get(),
				Error::<T>::ParamFail
			);
			let two_to_one_params = try_two_to_one_parameters()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to mint the asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;

			// Ensures the local commitment parameters have the matching checksum.
			let commit_param_checksum_local = COMMIT_PARAM.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to mint the asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;
			ensure!(
				commit_param_checksum_local == CommitParamChecksum::get(),
				Error::<T>::ParamFail
			);
			let commit_params = try_commitment_parameters()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to mint the asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;

			// Checks the validity of the mint data structure.
			let mint_sanity_check = data.sanity(&commit_params)
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to mint the asset with error: {:?}", e);
					Error::<T>::MintFail.into()
				})?;
			ensure!(mint_sanity_check, Error::<T>::MintFail);

			// Checks if the UTXO has been stored on-chain. If not, then it stores it. If it was
			// already stored, then we throw an error.
			let mut coin_shards = CoinShards::get();
			ensure!(!coin_shards.exist(&data.cm), Error::<T>::MantaCoinExist);
			coin_shards.update(&data.cm, &leaf_params, &two_to_one_params)
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to mint the asset with error: {:?}", e);
					Error::<T>::LedgerUpdateFail.into()
				})?;
			CoinShards::put(coin_shards);

			// Updates the encrypted asset list.
			let mut enc_value_list = EncryptedAssetList::get();
			enc_value_list.push(data.encrypted_note);
			EncryptedAssetList::put(enc_value_list);

			// Updates the account balances.
			PoolBalance::mutate(data.asset_id, |balance| *balance += data.value);
			Balances::<T>::mutate(&origin, data.asset_id, |balance| *balance -= data.value);

			// Deposits event.
			Self::deposit_event(RawEvent::Minted(origin, data.asset_id, data.value));
		}


		/// Manta's private transfer function that moves values from two
		/// sender's private tokens into two receiver tokens. A proof is required to
		/// make sure that this transaction is valid.
		/// Neither the values nor the identities are leaked during this process.
		#[weight = T::WeightInfo::private_transfer()]
		fn private_transfer(
			origin,
			data: PrivateTransferData,
		) {
			// SAFETY: This function does not know which `asset_id` is been transferred, so it
			// cannot check for initialization of the asset.

			// Checks that the origin is valid.
			let origin = ensure_signed(origin)?;

			// Ensures the local leaf parameters have the matching checksum.
			let leaf_param_checksum_local = HASH_PARAM.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to transfer the private asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;
			ensure!(
				leaf_param_checksum_local == LeafHashParamChecksum::get(),
				Error::<T>::ParamFail
			);
			let leaf_params = try_leaf_parameters()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to transfer the private asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;

			// Ensures the local two-to-one parameters have the matching checksum.
			let two_to_one_param_checksum_local = HASH_PARAM.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to transfer the private asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;
			ensure!(
				two_to_one_param_checksum_local == TwoToOneHashParamChecksum::get(),
				Error::<T>::ParamFail
			);
			let two_to_one_params = try_two_to_one_parameters()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to transfer the private asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;

			// Checks if the void numbers are already stored.
			let mut vn_list = VNList::get();
			ensure!(!vn_list.contains(&data.sender_0.void_number), Error::<T>::MantaCoinSpent);
			vn_list.push(data.sender_0.void_number);
			ensure!(!vn_list.contains(&data.sender_1.void_number), Error::<T>::MantaCoinSpent);
			vn_list.push(data.sender_1.void_number);

			// Checks that the senders know the current state of the ledger.
			let mut coin_shards = CoinShards::get();
			ensure!(coin_shards.check_root(&data.sender_0.root), Error::<T>::InvalidLedgerState);
			ensure!(coin_shards.check_root(&data.sender_1.root), Error::<T>::InvalidLedgerState);

			// NOTE: With sharding, there is no point to batch updating since the commitments are
			// likely to go to different shards.

			// Checks that the commitments are not in the list already and updates the coin list
			// accordingly.
			ensure!(!coin_shards.exist(&data.receiver_0.cm), Error::<T>::MantaCoinExist);
			coin_shards
				.update(&data.receiver_0.cm, &leaf_params, &two_to_one_params)
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to transfer the private asset with error: {:?}", e);
					Error::<T>::LedgerUpdateFail.into()
				})?;
			ensure!(!coin_shards.exist(&data.receiver_1.cm), Error::<T>::MantaCoinExist);
			coin_shards
				.update(&data.receiver_1.cm, &leaf_params, &two_to_one_params)
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to transfer the private asset with error: {:?}", e);
					Error::<T>::LedgerUpdateFail.into()
				})?;

			// Compares the checksum of the local verification key to the one stored in the ledger.
			let vk_checksum_local = TRANSFER_VK.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to transfer the private asset with error: {:?}", e);
					Error::<T>::ZkpParamFail.into()
				})?;
			ensure!(vk_checksum_local == PrivateTransferKeyChecksum::get(), Error::<T>::ZkpParamFail);

			// Checks the validity of transfer ZKP.
			ensure!(data.verify(&TRANSFER_VK), Error::<T>::ZkpVerificationFail);

			// FIXME: Revisit replay attack here.

			// Saves new encrypted assets.
			let mut enc_value_list = EncryptedAssetList::get();
			enc_value_list.push(data.receiver_0.encrypted_note);
			enc_value_list.push(data.receiver_1.encrypted_note);
			EncryptedAssetList::put(enc_value_list);

			// Saves UTXO set and void number set.
			CoinShards::put(coin_shards);
			VNList::put(vn_list);

			// Deposits event.
			Self::deposit_event(RawEvent::PrivateTransferred(origin));
		}

		/// Manta's reclaim function that moves values from two
		/// sender's private tokens into a receiver public account, and a private token.
		///
		/// A proof is required to make sure that this transaction is valid.
		/// Neither the values nor the identities is leaked during this process;
		/// except for the reclaimed amount.
		///
		/// # Note
		///
		/// At the moment, the reclaimed amount goes directly to `origin` account.
		// TODO: should we use a receiver different from the `origin` account?
		#[weight = T::WeightInfo::reclaim()]
		fn reclaim(
			origin,
			data: ReclaimData,
		) {
			// Checks that the asset has been initialized.
			ensure!(TotalSupply::contains_key(&data.asset_id), Error::<T>::BasecoinNotInit);

			// Checks that origin account is valid.
			let origin = ensure_signed(origin)?;

			// Ensures the local leaf parameters have the matching checksum.
			let leaf_param_checksum_local = HASH_PARAM.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to reclaim the private asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;
			ensure!(
				leaf_param_checksum_local == LeafHashParamChecksum::get(),
				Error::<T>::ParamFail
			);
			let leaf_params = try_leaf_parameters()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to reclaim the private asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;

			// Ensures the local two-to-one parameters have the matching checksum.
			let two_to_one_param_checksum_local = HASH_PARAM.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to reclaim the private asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;
			ensure!(
				two_to_one_param_checksum_local == TwoToOneHashParamChecksum::get(),
				Error::<T>::ParamFail
			);
			let two_to_one_params = try_two_to_one_parameters()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to reclaim the private asset with error: {:?}", e);
					Error::<T>::ParamFail.into()
				})?;

			// Checks that the balance is greater than amount to reclaim.
			ensure!(
				PoolBalance::get(data.asset_id) >= data.reclaim_value,
				Error::<T>::PoolOverdrawn
			);

			// Checks if the void numbers of the assets have already been posted to the ledger.
			let mut vn_list = VNList::get();
			ensure!(!vn_list.contains(&data.sender_0.void_number), Error::<T>::MantaCoinSpent);
			vn_list.push(data.sender_0.void_number);
			ensure!(!vn_list.contains(&data.sender_1.void_number), Error::<T>::MantaCoinSpent);
			vn_list.push(data.sender_1.void_number);

			// Checks that the senders know the current ledger state.
			let mut coin_shards = CoinShards::get();
			ensure!(coin_shards.check_root(&data.sender_0.root), Error::<T>::InvalidLedgerState);
			ensure!(coin_shards.check_root(&data.sender_1.root), Error::<T>::InvalidLedgerState);

			// Checks that the receiver UTXO is not stored already.
			ensure!(!coin_shards.exist(&data.receiver.cm), Error::<T>::MantaCoinSpent);

			// Checks that the checksum of the verifying key is the same as the one stored on-chain.
			let vk_checksum_local = RECLAIM_VK.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to reclaim the private asset with error: {:?}", e);
					Error::<T>::ZkpParamFail.into()
				})?;
			ensure!(vk_checksum_local == ReclaimKeyChecksum::get(), Error::<T>::ZkpParamFail);

			// Checks the validity of reclaim proof.
			ensure!(data.verify(&RECLAIM_VK), Error::<T>::ZkpVerificationFail);

			// FIXME: Revisit replay attack here.

			// Updates shards.
			coin_shards
				.update(&data.receiver.cm, &leaf_params, &two_to_one_params)
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to reclaim the private asset with error: {:?}", e);
					Error::<T>::LedgerUpdateFail.into()
				})?;
			CoinShards::put(coin_shards);

			// Updates encrypted asset list.
			let mut enc_value_list = EncryptedAssetList::get();
			enc_value_list.push(data.receiver.encrypted_note);
			EncryptedAssetList::put(enc_value_list);

			// Saves void number list.
			VNList::put(vn_list);

			// Update balances.
			PoolBalance::mutate(data.asset_id, |balance| *balance -= data.reclaim_value);
			Balances::<T>::mutate(&origin, data.asset_id, |balance| *balance += data.reclaim_value);

			// Deposits event.
			Self::deposit_event(RawEvent::Reclaimed(origin, data.asset_id, data.reclaim_value));
		}
	}
}

decl_event! {
	pub enum Event<T> where
		<T as frame_system::Config>::AccountId,
	{
		/// The asset was issued. \[owner, asset_id, total_supply\]
		Issued(AccountId, AssetId, AssetBalance),
		/// The asset was transferred. \[from, to, asset_id, value\]
		Transferred(AccountId, AccountId, AssetId, AssetBalance),
		/// The asset was minted to private. \[from, asset_id, value\]
		Minted(AccountId, AssetId, AssetBalance),
		/// A private transfer occured. \[signer\]
		PrivateTransferred(AccountId),
		/// The asset was reclaimed. \[to, asset_id, amount\]
		Reclaimed(AccountId, AssetId, AssetBalance),
	}
}

decl_error! {
	/// Error messages.
	pub enum Error for Module<T: Config> {
		/// This token has already been initiated.
		AlreadyInitialized,
		/// Transfer when not initialized.
		BasecoinNotInit,
		/// Transfer amount should be non-zero.
		AmountZero,
		/// Account balance must be greater than or equal to the transfer amount.
		BalanceLow,
		/// Balance should be non-zero.
		BalanceZero,
		/// Mint failed.
		MintFail,
		/// Ledger update failed.
		LedgerUpdateFail,
		/// MantaCoin already exists.
		MantaCoinExist,
		/// MantaCoin does not exist.
		MantaNotCoinExist,
		/// MantaCoin was already spent.
		MantaCoinSpent,
		/// ZKP parameter failed.
		ZkpParamFail,
		/// ZKP verification failed.
		ZkpVerificationFail,
		/// Ledger state was invalid.
		InvalidLedgerState,
		/// Pool was overdrawn.
		PoolOverdrawn,
		/// Parameters were invalid.
		ParamFail,
		/// Payload deserialization failed.
		PayloadDesFail,
	}
}

decl_storage! {
	trait Store for Module<T: Config> as Assets {
		/// The number of units of assets held by any given account.
		pub Balances: double_map
			hasher(blake2_128_concat) T::AccountId,
			hasher(blake2_128_concat) AssetId
			=> AssetBalance;

		/// The total unit supply of the asset.
		///
		/// If not stored in this map, then this asset is not initialized.
		pub TotalSupply: map hasher(blake2_128_concat) AssetId => AssetBalance;

		/// List of _void number_s.
		///
		/// A void number is also known as a `serial number` or `nullifier` in other protocols.
		/// Each coin has a unique void number, and if this number is revealed, the coin is voided.
		/// The ledger maintains a list of all void numbers.
		pub VNList get(fn vn_list): Vec<MantaRandomValue>;

		/// List of Coins that has ever been created.
		///
		/// We employ a sharding system to host all the coins for better concurrency.
		pub CoinShards get(fn coin_shards): MantaPrivateAssetLedger;

		/// List of encrypted assets.
		pub EncryptedAssetList get(fn encrypted_asset_list): Vec<MantaEciesCiphertext>;

		/// The balance of all minted coins for this `asset_id`.
		pub PoolBalance: map hasher(blake2_128_concat) AssetId => AssetBalance;

		/// The checksum of leaf hash parameter.
		pub LeafHashParamChecksum get(fn leaf_hash_param_checksum): [u8; 32];

		/// The checksum of two-to-one hash parameter.
		pub TwoToOneHashParamChecksum get(fn two_to_one_hash_param_checksum): [u8; 32];

		/// The checksum of commitment parameter.
		pub CommitParamChecksum get(fn commit_param_checksum): [u8; 32];

		/// The checksum of the private transfer zero-knowledge proof verifying key.
		pub PrivateTransferKeyChecksum get(fn private_transfer_key_checksum): [u8; 32];

		/// The checksum of the reclaim zero-knowledge proof verifying key.
		pub ReclaimKeyChecksum get(fn reclaim_key_checksum): [u8; 32];
	}
}

impl<T: Config> Module<T> {
	/// Gets the asset `id` balance of `who`.
	#[inline]
	pub fn balance(who: T::AccountId, id: AssetId) -> AssetBalance {
		Balances::<T>::get(who, id)
	}

	/// Gets the asset `id` total supply.
	#[inline]
	pub fn total_supply(id: AssetId) -> AssetBalance {
		TotalSupply::get(id)
	}
}
