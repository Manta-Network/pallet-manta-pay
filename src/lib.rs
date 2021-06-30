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
//! * `balance` - Get the asset balance of `who`.
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

use ark_std::vec::Vec;
use frame_support::{decl_error, decl_event, decl_module, decl_storage, ensure};
use frame_system::ensure_signed;
use manta_asset::SanityCheck;
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
		fn init_asset(origin,
			asset_id: u64,
			total: u64
		) {

			// if the asset_id has a total suply != 0, then this asset is initialized
			ensure!(
				!TotalSupply::contains_key(&asset_id),
				<Error<T>>::AlreadyInitialized
			);

			let origin = ensure_signed(origin)?;

			// for now we hard code the parameters generated from the following seed:
			//  * hash parameter seed: [1u8; 32]
			//  * commitment parameter seed: [2u8; 32]
			// We may want to pass those two in for `init`
			let hash_param = HashParam::deserialize(HASH_PARAM.data)
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to init the asset with error: {:?}", e);
					<Error<T>>::ParamFail.into()
				})?;

			let commit_param = CommitmentParam::deserialize(COMMIT_PARAM.data)
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to init the asset with error: {:?}", e);
					<Error<T>>::ParamFail.into()
				})?;

			let hash_param_checksum = hash_param.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to init the asset with error: {:?}", e);
					<Error<T>>::ParamFail.into()
				})?;

			let commit_param_checksum = commit_param.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to init the asset with error: {:?}", e);
					<Error<T>>::ParamFail.into()
				})?;

			HashParamChecksum::put(hash_param_checksum);
			CommitParamChecksum::put(commit_param_checksum);

			// push the checksums for ZKP verification keys to the ledger storage
			//
			// NOTE:
			//    this is is generated via
			//      let zkp_key = zkp::keys::manta_XXX_zkp_key_gen(&hash_param_seed, &commit_param_seed);
			//
			// for prototype, we use this function to generate the ZKP verification key
			// for product we should use a MPC protocol to build the ZKP verification key
			// and then deploy that vk
			//
			let transfer_key_digest = TRANSFER_PK.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to init the asset with error: {:?}", e);
					<Error<T>>::ParamFail.into()
				})?;

			TransferZKPKeyChecksum::put(transfer_key_digest);

			let reclaim_key_digest = RECLAIM_PK.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to init the asset with error: {:?}", e);
					<Error<T>>::ParamFail.into()
				})?;

			ReclaimZKPKeyChecksum::put(reclaim_key_digest);

			// deposit the event then update the storage
			Self::deposit_event(RawEvent::Issued(asset_id, origin.clone(), total));

			// coin_shards are 256 lists of commitments
			let coin_shards = MantaPrivateAssetLedger::default();
			CoinShards::put(coin_shards);

			// initialize the asset with `total` number of supplies
			// the total number of private asset (pool balance) remain 0
			// the assets is credit to the sender's account
			PoolBalance::insert(asset_id, 0);
			TotalSupply::insert(asset_id, total);
			<Balances<T>>::insert(&origin, asset_id, total);

			VNList::put(Vec::<[u8; 32]>::new());
			EncValueList::put(Vec::<[u8; 16]>::new());

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
		fn transfer_asset(origin,
			target: <T::Lookup as StaticLookup>::Source,
			asset_id: u64,
			amount: u64
		) {

			// if the asset_id has a total suply == 0, then this asset is initialized
			ensure!(
				TotalSupply::contains_key(&asset_id),
				<Error<T>>::BasecoinNotInit
			);
			let origin = ensure_signed(origin)?;

			let origin_account = origin.clone();
			let origin_balance = <Balances<T>>::get(&origin_account, asset_id);
			let target = T::Lookup::lookup(target)?;
			ensure!(!amount.is_zero(), Error::<T>::AmountZero);
			ensure!(origin_balance >= amount, Error::<T>::BalanceLow);
			Self::deposit_event(
				RawEvent::Transferred(asset_id, origin, target.clone(), amount)
			);

			// todo: figure out the different between insert and mutate.
			<Balances<T>>::insert(origin_account, asset_id, origin_balance - amount);
			<Balances<T>>::mutate(target, asset_id, |balance| *balance += amount);
		}

		/// Given an amount, and relevant data, mint the token to the ledger
		#[weight = T::WeightInfo::mint_private_asset()]
		fn mint_private_asset(origin,
			payload: MintPayload
		) {
			// todo: Implement the fix denomination method

			// parse the input_data into input
			let input =  MintData::deserialize(payload.as_ref())
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to mint the asset with error: {:?}", e);
					<Error<T>>::PayloadDesFail.into()
				})?;

			// if the asset_id has a total supply > 0, then this asset is initialized
			ensure!(
				TotalSupply::contains_key(&input.asset_id),
				<Error<T>>::BasecoinNotInit
			);

			// get the original balance
			let origin = ensure_signed(origin)?;
			let origin_account = origin.clone();
			let origin_balance = <Balances<T>>::get(&origin_account, input.asset_id);
			ensure!(origin_balance >= input.amount, Error::<T>::BalanceLow);

			// get the parameter checksum from the ledger
			// and make sure the parameters match
			let hash_param_checksum_local = HASH_PARAM.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to mint the asset with error: {:?}", e);
					<Error<T>>::ParamFail.into()
				})?;

			let commit_param_checksum_local = COMMIT_PARAM.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to mint the asset with error: {:?}", e);
					<Error<T>>::ParamFail.into()
				})?;

			let hash_param_checksum = HashParamChecksum::get();
			let commit_param_checksum = CommitParamChecksum::get();
			ensure!(
				hash_param_checksum_local == hash_param_checksum,
				<Error<T>>::ParamFail
			);
			ensure!(
				commit_param_checksum_local == commit_param_checksum,
				<Error<T>>::ParamFail
			);

			let hash_param = HashParam::deserialize(HASH_PARAM.data)
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to mint the asset with error: {:?}", e);
					<Error<T>>::ParamFail.into()
				})?;

			let commit_param = CommitmentParam::deserialize(COMMIT_PARAM.data)
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to mint the asset with error: {:?}", e);
					<Error<T>>::ParamFail.into()
				})?;

			// check the validity of the commitment
			let res = input.sanity(&commit_param)
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to mint the asset with error: {:?}", e);
					<Error<T>>::MintFail.into()
				})?;

			ensure!(
				res,
				<Error<T>>::MintFail
			);

			// check cm is not in the ledger
			let mut coin_shards = CoinShards::get();
			ensure!(
				!coin_shards.exist(&input.cm),
				Error::<T>::MantaCoinExist
			);

			// update the shards
			coin_shards.update(&input.cm, hash_param)
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to mint the asset with error: {:?}", e);
					<Error<T>>::LedgerUpdateFail.into()
				})?;

			// update enc_value_list
			let mut enc_value_list = EncValueList::get();
			enc_value_list.push(input.ciphertext);
			let old_pool_balance = PoolBalance::get(input.asset_id);
		
			// write back to ledger storage
			Self::deposit_event(
				RawEvent::Minted(input.asset_id, origin, input.amount)
			);

			CoinShards::put(coin_shards);
			EncValueList::put(enc_value_list);
			PoolBalance::mutate(
				input.asset_id,
				|balance| *balance = old_pool_balance + input.amount
			);
			<Balances<T>>::mutate(
				origin_account,
				input.asset_id,
				|balance| *balance =  origin_balance - input.amount
			);
		}


		/// Manta's private transfer function that moves values from two
		/// sender's private tokens into two receiver tokens. A proof is required to
		/// make sure that this transaction is valid.
		/// Neither the values nor the identities is leaked during this process.
		#[weight = T::WeightInfo::private_transfer()]
		fn private_transfer(origin,
			payload: PrivateTransferPayload,
		) {
			// this function does not know which asset_id is been transferred.
			// so there will not be an initialization check

			let data = PrivateTransferData::deserialize(payload.as_ref())
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to transfer the private asset with error: {:?}", e);
					<Error<T>>::PayloadDesFail.into()
				})?;

			let origin = ensure_signed(origin)?;

			// get the parameter checksum from the ledger
			// and make sure the parameters match
			let hash_param_checksum_local = HASH_PARAM.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to transfer the private asset with error: {:?}", e);
					<Error<T>>::ParamFail.into()
				})?;

			let hash_param_checksum = HashParamChecksum::get();
			ensure!(
				hash_param_checksum_local == hash_param_checksum,
				<Error<T>>::ParamFail
			);
			let hash_param = HashParam::deserialize(HASH_PARAM.data)
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to transfer the private asset with error: {:?}", e);
					<Error<T>>::ParamFail.into()
				})?;

			// check if vn_old already spent
			let mut vn_list = VNList::get();
			ensure!(
				!vn_list.contains(&data.sender_1.void_number),
				<Error<T>>::MantaCoinSpent
			);
			vn_list.push(data.sender_1.void_number);
			ensure!(
				!vn_list.contains(&data.sender_2.void_number),
				<Error<T>>::MantaCoinSpent
			);
			vn_list.push(data.sender_2.void_number);

			// get the ledger state from the ledger
			// and check the validity of the state
			let mut coin_shards = CoinShards::get();
			ensure!(
				coin_shards.check_root(&data.sender_1.root),
				<Error<T>>::InvalidLedgerState
			);
			ensure!(
				coin_shards.check_root(&data.sender_2.root),
				<Error<T>>::InvalidLedgerState
			);

			// check the commitment are not in the list already
			// and update coin list
			// with sharding, there is no point to batch update
			// since the commitments are likely to go to different shards
			ensure!(
				!coin_shards.exist(&data.receiver_1.cm),
				<Error<T>>::MantaCoinExist
			);
			coin_shards
				.update(&data.receiver_1.cm, hash_param.clone())
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to transfer the private asset with error: {:?}", e);
					<Error<T>>::LedgerUpdateFail.into()
				})?;

			ensure!(
				!coin_shards.exist(&data.receiver_2.cm),
				<Error<T>>::MantaCoinExist
			);
			coin_shards
				.update(&data.receiver_2.cm, hash_param)
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to transfer the private asset with error: {:?}", e);
					<Error<T>>::LedgerUpdateFail.into()
				})?;

			// get the verification key from the ledger
			let transfer_vk_checksum = TransferZKPKeyChecksum::get();
			let transfer_vk = TRANSFER_PK;
			let transfer_vk_checksum_local = transfer_vk.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to transfer the private asset with error: {:?}", e);
					<Error<T>>::ZkpParamFail.into()
				})?;

			ensure!(
				transfer_vk_checksum_local == transfer_vk_checksum,
				<Error<T>>::ZkpParamFail,
			);

			// check validity of zkp
			ensure!(
				data.verify(&transfer_vk),
				<Error<T>>::ZkpVerificationFail,
			);

			// TODO: revisit replay attack here

			// update ledger storage
			let mut enc_value_list = EncValueList::get();
			enc_value_list.push(data.receiver_1.cipher);
			enc_value_list.push(data.receiver_2.cipher);

			Self::deposit_event(RawEvent::PrivateTransferred(origin));
			CoinShards::put(coin_shards);
			VNList::put(vn_list);
			EncValueList::put(enc_value_list);
		}

		/// Manta's reclaim function that moves values from two
		/// sender's private tokens into a receiver public account, and a private token.
		/// A proof is required to
		/// make sure that this transaction is valid.
		/// Neither the values nor the identities is leaked during this process;
		/// except for the reclaimed amount.
		/// At the moment, the reclaimed amount goes directly to `origin` account.
		/// __TODO__: shall we use a different receiver rather than `origin`?
		#[weight = T::WeightInfo::reclaim()]
		fn reclaim(origin,
			payload: ReclaimPayload,
		) {

			let data = ReclaimData::deserialize(payload.as_ref())
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to reclaim the private asset with error: {:?}", e);
					<Error<T>>::PayloadDesFail.into()
				})?;

			// if the asset_id has a total suply == 0, then this asset is initialized
			ensure!(
				TotalSupply::contains_key(&data.asset_id),
				<Error<T>>::BasecoinNotInit
			);

			let origin = ensure_signed(origin)?;
			let origin_account = origin.clone();
			let origin_balance = <Balances<T>>::get(&origin, data.asset_id);

			// get the parameter checksum from the ledger
			// and make sure the parameters match
			let hash_param_checksum_local = HASH_PARAM.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to reclaim the private asset with error: {:?}", e);
					<Error<T>>::ParamFail.into()
				})?;

			let hash_param_checksum = HashParamChecksum::get();
			ensure!(
				hash_param_checksum_local == hash_param_checksum,
				<Error<T>>::ParamFail
			);
			let hash_param = HashParam::deserialize(HASH_PARAM.data)
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to reclaim the private asset with error: {:?}", e);
					<Error<T>>::ParamFail.into()
				})?;

			// check the balance is greater than amount
			let mut pool = PoolBalance::get(data.asset_id);
			ensure!(pool>=data.reclaim_amount, <Error<T>>::PoolOverdrawn);
			pool -= data.reclaim_amount;

			// check if sn_old already spent
			let mut vn_list = VNList::get();
			ensure!(
				!vn_list.contains(&data.sender_1.void_number),
				<Error<T>>::MantaCoinSpent
			);
			vn_list.push(data.sender_1.void_number);
			ensure!(
				!vn_list.contains(&data.sender_2.void_number),
				<Error<T>>::MantaCoinSpent
			);
			vn_list.push(data.sender_2.void_number);

			// get the coin list
			let mut coin_shards = CoinShards::get();

			// get the verification key from the ledger
			let reclaim_vk_checksum = ReclaimZKPKeyChecksum::get();
			let reclaim_vk = RECLAIM_PK;
			let reclaim_vk_checksum_local = reclaim_vk.get_checksum()
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to reclaim the private asset with error: {:?}", e);
					<Error<T>>::ZkpParamFail.into()
				})?;

			ensure!(
				reclaim_vk_checksum_local == reclaim_vk_checksum,
				<Error<T>>::ZkpParamFail
			);
			// get the ledger state from the ledger
			// and check the validity of the state
			ensure!(
				coin_shards.check_root(&data.sender_1.root),
				<Error<T>>::InvalidLedgerState
			);
			ensure!(
				coin_shards.check_root(&data.sender_2.root),
				<Error<T>>::InvalidLedgerState
			);
			// check the commitment are not in the list already
			ensure!(
				!coin_shards.exist(&data.receiver.cm),
				<Error<T>>::MantaCoinSpent
			);


			// check validity of zkp
			ensure!(
				data.verify(&reclaim_vk),
				<Error<T>>::ZkpVerificationFail,
			);

			// TODO: revisit replay attack here

			// update ledger storage
			let mut enc_value_list = EncValueList::get();
			enc_value_list.push(data.receiver.cipher);

			coin_shards
				.update(&data.receiver.cm, hash_param)
				.map_err::<DispatchError, _>(|e| {
					log::error!(target: "manta-pay", "failed to reclaim the private asset with error: {:?}", e);
					<Error<T>>::LedgerUpdateFail.into()
				})?;

			CoinShards::put(coin_shards);

			Self::deposit_event(
				RawEvent::PrivateReclaimed(data.asset_id, origin, data.reclaim_amount)
			);
			VNList::put(vn_list);
			PoolBalance::mutate(data.asset_id, |balance| *balance = pool);
			EncValueList::put(enc_value_list);
			<Balances<T>>::mutate(
				origin_account,
				data.asset_id,
				|balance| *balance = origin_balance + data.reclaim_amount
			);
		}
	}
}

decl_event! {
	pub enum Event<T> where
		<T as frame_system::Config>::AccountId,
	{
		/// The asset was issued. \[asset_id, owner, total_supply\]
		Issued(u64, AccountId, u64),
		/// The asset was transferred. \[from, to, amount\]
		Transferred(u64, AccountId, AccountId, u64),
		/// The asset was minted to private
		Minted(u64, AccountId, u64),
		/// Private transfer
		PrivateTransferred(AccountId),
		/// The assets was reclaimed
		PrivateReclaimed(u64, AccountId, u64),
	}
}

decl_error! {
	/// Error messages.
	pub enum Error for Module<T: Config> {
		/// This token has already been initiated
		AlreadyInitialized,
		/// Transfer when not initialized
		BasecoinNotInit,
		/// Transfer amount should be non-zero
		AmountZero,
		/// Account balance must be greater than or equal to the transfer amount
		BalanceLow,
		/// Balance should be non-zero
		BalanceZero,
		/// Mint failure
		MintFail,
		/// Mint failure
		LedgerUpdateFail,
		/// MantaCoin exist
		MantaCoinExist,
		/// MantaCoin does not exist
		MantaNotCoinExist,
		/// MantaCoin already spend
		MantaCoinSpent,
		/// ZKP parameter failed
		ZkpParamFail,
		/// ZKP verification failed
		ZkpVerificationFail,
		/// invalid ledger state
		InvalidLedgerState,
		/// Pool overdrawn
		PoolOverdrawn,
		/// Invalid parameters
		ParamFail,
		/// Payload deserialization fail
		PayloadDesFail,
	}
}

decl_storage! {
	trait Store for Module<T: Config> as Assets {
		/// The number of units of assets held by any given account.
		pub Balances: double_map
			hasher(blake2_128_concat) T::AccountId,
			hasher(blake2_128_concat) u64
			=> u64;

		/// The total unit supply of the asset.
		/// If 0, then this asset is not initialized.
		pub TotalSupply: map hasher(blake2_128_concat) u64 => u64;

		/// List of _void number_s.
		/// A void number is also known as a `serial number` or `nullifier` in other protocols.
		/// Each coin has a unique void number, and if this number is revealed,
		/// the coin is voided.
		/// The ledger maintains a list of all void numbers.
		pub VNList get(fn vn_list): Vec<[u8; 32]>;

		/// List of Coins that has ever been created.
		/// We employ a sharding system to host all the coins
		/// for better concurrency.
		pub CoinShards get(fn coin_shards): MantaPrivateAssetLedger;

		/// List of encrypted values.
		pub EncValueList get(fn enc_value_list): Vec<[u8; 16]>;

		/// The balance of all minted coins for this asset_id.
		pub PoolBalance: map hasher(blake2_128_concat) u64 => u64;

		/// The checksum of hash parameter.
		pub HashParamChecksum get(fn hash_param_checksum): [u8; 32];

		/// The checksum of commitment parameter.
		pub CommitParamChecksum get(fn commit_param_checksum): [u8; 32];

		/// The verification key for zero-knowledge proof for transfer protocol.
		/// At the moment we are storing the whole serialized key
		/// in the blockchain storage.
		pub TransferZKPKeyChecksum get(fn transfer_zkp_vk_checksum): [u8; 32];

		/// The verification key for zero-knowledge proof for reclaim protocol.
		/// At the moment we are storing the whole serialized key
		/// in the blockchain storage.
		pub ReclaimZKPKeyChecksum get(fn reclaim_zkp_vk_checksum): [u8; 32];
	}
}

// The main implementation block for the module.
impl<T: Config> Module<T> {
	// Public immutables

	/// Get the asset `id` balance of `who`.
	pub fn balance(who: T::AccountId, what: u64) -> u64 {
		<Balances<T>>::get(who, what)
	}

	/// Get the asset `id` total supply.
	pub fn total_supply(what: u64) -> u64 {
		TotalSupply::get(what)
	}
}
