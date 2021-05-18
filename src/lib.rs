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
//!	two UTXOs to another UTXO, and converting the remaining private assets back to public
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
//!	* `private_transfer` - Transfer two input UTXOs into two output UTXOs. Require that 1) the input UTXOs are
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
#![cfg_attr(not(feature = "std"), no_std)]

mod ledger;
mod payload;
mod runtime_benchmark;
mod zkp;

#[cfg(test)]
mod test;
#[cfg(test)]
#[macro_use]
extern crate std;

pub use ledger::{Shard, Shards};
pub use manta_crypto::MantaSerDes;
pub use payload::*;
pub use zkp::*;

use ark_std::vec::Vec;
use frame_support::{decl_error, decl_event, decl_module, decl_storage, ensure};
use frame_system::ensure_signed;
use ledger::LedgerSharding;
use manta_crypto::*;
use pallet_manta_asset::SanityCheck;
use sp_runtime::traits::{StaticLookup, Zero};
use sp_std::prelude::*;

/// The module configuration trait.
pub trait Config: frame_system::Config {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Config>::Event>;
}

decl_module! {
	pub struct Module<T: Config> for enum Call where origin: T::Origin {
		type Error = Error<T>;

		fn deposit_event() = default;
		/// Issue a new class of fungible assets. There are, and will only ever be, `total`
		/// such assets and they'll all belong to the `origin` initially. It will have an
		/// identifier `AssetId` instance: this will be specified in the `Issued` event.
		/// __TODO__: check the weights is correct
		/// # <weight>
		/// - `O(1)`
		/// - 1 storage mutation (codec `O(1)`).
		/// - 2 storage writes (codec `O(1)`).
		/// - 1 event.
		/// # </weight>
		#[weight = 0]
		fn init_asset(origin, total: u64) {

			ensure!(!Self::is_init(), <Error<T>>::AlreadyInitialized);
			let origin = ensure_signed(origin)?;

			// for now we hard code the parameters generated from the following seed:
			//  * hash parameter seed: [1u8; 32]
			//  * commitment parameter seed: [2u8; 32]
			// We may want to pass those two in for `init`
			let hash_param = HashParam::deserialize(HASH_PARAM.data);
			let commit_param = CommitmentParam::deserialize(COMMIT_PARAM.data);
			let hash_param_checksum = hash_param.get_checksum();
			let commit_param_checksum = commit_param.get_checksum();

			// push the ZKP verification key to the ledger storage
			//
			// NOTE:
			//    this is is generated via
			//      let zkp_key = priv_coin::manta_XXX_zkp_key_gen(&hash_param_seed, &commit_param_seed);
			//
			// for prototype, we use this function to generate the ZKP verification key
			// for product we should use a MPC protocol to build the ZKP verification key
			// and then deploy that vk
			//
			let transfer_key_digest = TRANSFER_PK.get_checksum();
			TransferZKPKeyChecksum::put(transfer_key_digest);

			let reclaim_key_digest = RECLAIM_PK.get_checksum();
			ReclaimZKPKeyChecksum::put(reclaim_key_digest);

			// coin_shards are a 256 lists of commitments
			let coin_shards = Shards::default();
			CoinShards::put(coin_shards);

			PoolBalance::put(0);
			VNList::put(Vec::<[u8; 32]>::new());
			EncValueList::put(Vec::<[u8; 16]>::new());
			<Balances<T>>::insert(&origin, total);
			<TotalSupply>::put(total);
			Self::deposit_event(RawEvent::Issued(origin, total));
			Init::put(true);
			HashParamChecksum::put(hash_param_checksum);
			CommitParamChecksum::put(commit_param_checksum);
		}

		/// Move some assets from one holder to another.
		/// __TODO__: check the weights is correct
		///
		/// # <weight>
		/// - `O(1)`
		/// - 1 static lookup
		/// - 2 storage mutations (codec `O(1)`).
		/// - 1 event.
		/// # </weight>
		#[weight = 0]
		fn transfer_asset(origin,
			target: <T::Lookup as StaticLookup>::Source,
			amount: u64
		) {
			ensure!(Self::is_init(), <Error<T>>::BasecoinNotInit);
			let origin = ensure_signed(origin)?;

			let origin_account = origin.clone();
			let origin_balance = <Balances<T>>::get(&origin_account);
			let target = T::Lookup::lookup(target)?;
			ensure!(!amount.is_zero(), Error::<T>::AmountZero);
			ensure!(origin_balance >= amount, Error::<T>::BalanceLow);
			Self::deposit_event(RawEvent::Transferred(origin, target.clone(), amount));
			<Balances<T>>::insert(origin_account, origin_balance - amount);
			<Balances<T>>::mutate(target, |balance| *balance += amount);
		}

		/// Given an amount, and relevant data, mint the token to the ledger
		#[weight = 0]
		fn mint_private_asset(origin,
			payload: [u8; 104]
		) {
			// todo: Implement the fix denomination method

			// parse the input_data into input
			let input = MintData::deserialize(payload.as_ref());

			// get the original balance
			ensure!(Self::is_init(), <Error<T>>::BasecoinNotInit);
			let origin = ensure_signed(origin)?;
			let origin_account = origin.clone();
			ensure!(!input.amount.is_zero(), Error::<T>::AmountZero);
			let origin_balance = <Balances<T>>::get(&origin_account);
			ensure!(origin_balance >= input.amount, Error::<T>::BalanceLow);

			// get the parameter checksum from the ledger
			// and make sure the parameters match
			let hash_param_checksum_local = HASH_PARAM.get_checksum();
			let commit_param_checksum_local = COMMIT_PARAM.get_checksum();

			let hash_param_checksum = HashParamChecksum::get();
			let commit_param_checksum = CommitParamChecksum::get();
			ensure!(
				hash_param_checksum_local == hash_param_checksum,
				<Error<T>>::MintFail
			);
			ensure!(
				commit_param_checksum_local == commit_param_checksum,
				<Error<T>>::MintFail
			);

			let hash_param = HashParam::deserialize(HASH_PARAM.data);
			let commit_param = CommitmentParam::deserialize(COMMIT_PARAM.data);

			// check the validity of the commitment
			ensure!(
				input.sanity(&commit_param),
				<Error<T>>::MintFail
			);

			// check cm is not in the ledger
			let mut coin_shards = CoinShards::get();
			ensure!(
				!coin_shards.exist(&input.cm),
				Error::<T>::MantaCoinExist
			);

			// update the shards
			coin_shards.update(&input.cm, hash_param);

			// write back to ledger storage
			Self::deposit_event(RawEvent::Minted(origin, input.amount));
			CoinShards::put(coin_shards);

			let old_pool_balance = PoolBalance::get();
			PoolBalance::put(old_pool_balance + input.amount);
			<Balances<T>>::insert(origin_account, origin_balance - input.amount);
		}


		/// Manta's private transfer function that moves values from two
		/// sender's private tokens into two receiver tokens. A proof is required to
		/// make sure that this transaction is valid.
		/// Neither the values nor the identities is leaked during this process.
		#[weight = 0]
		fn private_transfer(origin,
			payload: [u8; 544],
		) {
			let data = PrivateTransferData::deserialize(payload.as_ref());
			ensure!(Self::is_init(), <Error<T>>::BasecoinNotInit);
			let origin = ensure_signed(origin)?;

			// get the parameter checksum from the ledger
			// and make sure the parameters match
			let hash_param_checksum_local = HASH_PARAM.get_checksum();

			let hash_param_checksum = HashParamChecksum::get();
			ensure!(
				hash_param_checksum_local == hash_param_checksum,
				<Error<T>>::MintFail
			);
			let hash_param = HashParam::deserialize(HASH_PARAM.data);

			// check if vn_old already spent
			let mut sn_list = VNList::get();
			ensure!(
				!sn_list.contains(&data.sender_1.void_number),
				<Error<T>>::MantaCoinSpent
			);
			sn_list.push(data.sender_1.void_number);
			ensure!(
				!sn_list.contains(&data.sender_2.void_number),
				<Error<T>>::MantaCoinSpent
			);
			sn_list.push(data.sender_2.void_number);

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
			coin_shards.update(&data.receiver_1.cm, hash_param.clone());
			ensure!(
				!coin_shards.exist(&data.receiver_2.cm),
				<Error<T>>::MantaCoinExist
			);
			coin_shards.update(&data.receiver_2.cm, hash_param);

			// get the verification key from the ledger
			let transfer_vk_checksum = TransferZKPKeyChecksum::get();
			let transfer_vk = TRANSFER_PK;

			ensure!(
				transfer_vk.get_checksum() == transfer_vk_checksum,
				<Error<T>>::ZkpParamFail,
			);

			// check validity of zkp
			ensure!(
				data.sanity(&transfer_vk),
				<Error<T>>::ZkpVerificationFail,
			);

			// TODO: revisit replay attack here

			// update ledger storage
			let mut enc_value_list = EncValueList::get();
			enc_value_list.push(data.receiver_1.cipher);
			enc_value_list.push(data.receiver_2.cipher);

			Self::deposit_event(RawEvent::PrivateTransferred(origin));
			CoinShards::put(coin_shards);
			VNList::put(sn_list);
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
		#[weight = 0]
		fn reclaim(origin,
			payload: [u8; 472],
		) {
			let data = ReclaimData::deserialize(payload.as_ref());

			let origin = ensure_signed(origin)?;
			let origin_account = origin.clone();
			let origin_balance = <Balances<T>>::get(&origin);
			ensure!(Self::is_init(), <Error<T>>::BasecoinNotInit);


			// get the parameter checksum from the ledger
			// and make sure the parameters match
			let hash_param_checksum_local = HASH_PARAM.get_checksum();

			let hash_param_checksum = HashParamChecksum::get();
			ensure!(
				hash_param_checksum_local == hash_param_checksum,
				<Error<T>>::MintFail
			);
			let hash_param = HashParam::deserialize(HASH_PARAM.data);

			// check the balance is greater than amount
			let mut pool = PoolBalance::get();
			ensure!(pool>=data.reclaim_amount, <Error<T>>::PoolOverdrawn);
			pool -= data.reclaim_amount;

			// check if sn_old already spent
			let mut sn_list = VNList::get();
			ensure!(
				!sn_list.contains(&data.sender_1.void_number),
				<Error<T>>::MantaCoinSpent
			);
			sn_list.push(data.sender_1.void_number);
			ensure!(
				!sn_list.contains(&data.sender_2.void_number),
				<Error<T>>::MantaCoinSpent
			);
			sn_list.push(data.sender_2.void_number);

			// get the coin list
			let mut coin_shards = CoinShards::get();

			// get the verification key from the ledger
			let reclaim_vk_checksum = ReclaimZKPKeyChecksum::get();
			let reclaim_vk = RECLAIM_PK;
			ensure!(
				reclaim_vk.get_checksum() == reclaim_vk_checksum,
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
				data.sanity(&reclaim_vk),
				<Error<T>>::ZkpVerificationFail,
			);

			// TODO: revisit replay attack here

			// update ledger storage
			let mut enc_value_list = EncValueList::get();
			enc_value_list.push(data.receiver.cipher);


			coin_shards.update(&data.receiver.cm, hash_param);
			CoinShards::put(coin_shards);

			Self::deposit_event(RawEvent::PrivateReclaimed(origin));
			VNList::put(sn_list);
			PoolBalance::put(pool);
			EncValueList::put(enc_value_list);
			<Balances<T>>::insert(origin_account, origin_balance + data.reclaim_amount);
		}
	}
}

decl_event! {
	pub enum Event<T> where
		<T as frame_system::Config>::AccountId,
	{
		/// The asset was issued. \[owner, total_supply\]
		Issued(AccountId, u64),
		/// The asset was transferred. \[from, to, amount\]
		Transferred(AccountId, AccountId, u64),
		/// The asset was minted to private
		Minted(AccountId, u64),
		/// Private transfer
		PrivateTransferred(AccountId),
		/// The assets was reclaimed
		PrivateReclaimed(AccountId),
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
	}
}

decl_storage! {
	trait Store for Module<T: Config> as Assets {
		/// The number of units of assets held by any given account.
		pub Balances: map hasher(blake2_128_concat) T::AccountId => u64;

		/// The total unit supply of the asset.
		pub TotalSupply get(fn total_supply): u64;

		/// Returns a boolean: is this token already initialized (can only initiate once)
		pub Init get(fn is_init): bool;

		/// List of _void number_s.
		/// A void number is also known as a `serial number` in other protocols.
		/// Each coin has a unique void number, and if this number is revealed,
		/// the coin is voided.
		/// The ledger maintains a list of all void numbers.
		pub VNList get(fn vn_list): Vec<[u8; 32]>;

		/// List of Coins that has ever been created.
		/// We employ a sharding system to host all the coins
		/// for better concurrency.
		pub CoinShards get(fn coin_shards): Shards;

		/// List of encrypted values.
		pub EncValueList get(fn enc_value_list): Vec<[u8; 16]>;

		/// The balance of all minted coins.
		pub PoolBalance get(fn pool_balance): u64;

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
	pub fn balance(who: T::AccountId) -> u64 {
		<Balances<T>>::get(who)
	}
}
