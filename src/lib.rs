// This file is part of Substrate.

// Copyright (C) 2017-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # Manta DAP Module
//!
//! A simple, secure module for manta anounymous payment
//!
//! ## Overview
//!
//! The Assets module provides functionality for asset management of fungible asset classes
//! with a fixed supply, including:
//!
//! * Asset Issuance
//! * Asset Transfer
//!
//!
//! To use it in your runtime, you need to implement the assets [`Trait`](./trait.Trait.html).
//!
//! The supported dispatchable functions are documented in the [`Call`](./enum.Call.html) enum.
//!
//! ### Terminology
//!
//! * **Asset issuance:** The creation of the asset (note: this asset can only be created once)
//! * **Asset transfer:** The action of transferring assets from one account to another.
//! * **Asset destruction:** The process of an account removing its entire holding of an asset.
//!
//! The assets system in Substrate is designed to make the following possible:
//!
//! * Issue a unique asset to its creator's account.
//! * Move assets between accounts.
//!
//! ## Interface
//!
//! ### Dispatchable Functions
//!
//! * `issue` - Issues the total supply of a new fungible asset to the account of the caller of the function.
//! * `transfer` - Transfers an `amount` of units of fungible asset `id` from the balance of
//! the function caller's account (`origin`) to a `target` account.
//! * `destroy` - Destroys the entire holding of a fungible asset `id` associated with the account
//! that called the function.
//!
//! Please refer to the [`Call`](./enum.Call.html) enum and its associated variants for documentation on each function.
//!
//! ### Public Functions
//! <!-- Original author of descriptions: @gavofyork -->
//!
//! * `balance` - Get the asset balance of `who`.
//! * `total_supply` - Get the total supply of an asset `id`.
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
// #![macro_use]
// extern crate frame_benchmarking;

extern crate ark_crypto_primitives;
extern crate ark_ed_on_bls12_381;
extern crate ark_groth16;
extern crate ark_r1cs_std;
extern crate ark_relations;
extern crate ark_serialize;
extern crate ark_std;
extern crate blake2;
extern crate generic_array;
extern crate rand_chacha;
extern crate x25519_dalek;

mod benchmark;
pub mod dh;
pub mod manta_token;
pub mod param;
pub mod priv_coin;
pub mod reclaim;
pub mod serdes;
pub mod transfer;

#[cfg(test)]
pub mod test;

use ark_std::vec::Vec;
use frame_support::{decl_error, decl_event, decl_module, decl_storage, ensure};
use frame_system::ensure_signed;
use manta_token::*;
use param::{COMPARAMBYTES, HASHPARAMBYTES, RECLAIMVKBYTES, TRANSFERVKBYTES, *};
use serdes::{Checksum, MantaSerDes};
use sp_runtime::traits::{StaticLookup, Zero};

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
		///
		/// # <weight>
		/// - `O(1)`
		/// - 1 storage mutation (codec `O(1)`).
		/// - 2 storage writes (condec `O(1)`).
		/// - 1 event.
		/// # </weight>
		#[weight = 0]
		fn init(origin, total: u64) {

			ensure!(!Self::is_init(), <Error<T>>::AlreadyInitialized);
			let origin = ensure_signed(origin)?;

			// for now we hard code the parameters generated from the following seed:
			//  * hash parameter seed: [1u8; 32]
			//  * commitment parameter seed: [2u8; 32]
			// We may want to pass those two in for `init`
			let hash_param = HashParam::deserialize(HASHPARAMBYTES.as_ref());
			let commit_param = MantaCoinCommitmentParam::deserialize(COMPARAMBYTES.as_ref());
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
			// and then depoly that vk
			//
			TransferZKPKey::put(TRANSFERVKBYTES.to_vec());
			ReclaimZKPKey::put(RECLAIMVKBYTES.to_vec());

			CoinList::put(Vec::<[u8;32]>::new());
			LedgerState::put([4u8; 32]);
			PoolBalance::put(0);
			SNList::put(Vec::<[u8; 32]>::new());
			EncValueList::put(Vec::<[u8; 16]>::new());
			<Balances<T>>::insert(&origin, total);
			<TotalSupply>::put(total);
			Self::deposit_event(RawEvent::Issued(origin, total));
			Init::put(true);
			HashParamChecksum::put(hash_param_checksum);
			CommitParamChecksum::put(commit_param_checksum);
		}

		/// Move some assets from one holder to another.
		///
		/// # <weight>
		/// - `O(1)`
		/// - 1 static lookup
		/// - 2 storage mutations (codec `O(1)`).
		/// - 1 event.
		/// # </weight>
		#[weight = 0]
		fn transfer(origin,
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

		/// Mint
		/// TODO: rename arguments
		/// TODO: do we need to store k and s?
		#[weight = 0]
		fn mint(origin,
			amount: u64,
			input_data: [u8; 96]
		) {
			// todo: Implement the fix denomination method

			// parse the input_data into input
			let input = MintData::deserialize(input_data.as_ref());

			// get the original balance
			ensure!(Self::is_init(), <Error<T>>::BasecoinNotInit);
			let origin = ensure_signed(origin)?;
			let origin_account = origin.clone();
			ensure!(!amount.is_zero(), Error::<T>::AmountZero);
			let origin_balance = <Balances<T>>::get(&origin_account);
			ensure!(origin_balance >= amount, Error::<T>::BalanceLow);

			let hash_param = HashParam::deserialize(HASHPARAMBYTES.as_ref());
			let commit_param = MantaCoinCommitmentParam::deserialize(COMPARAMBYTES.as_ref());
			let hash_param_checksum_local = hash_param.get_checksum();
			let commit_param_checksum_local = commit_param.get_checksum();


			// get the parameter checksum from the ledger
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
			// todo: checksum ZKP verification eky



			// check the validity of the commitment
			ensure!(
				input.sanity_check(amount, &commit_param),
				<Error<T>>::MintFail
			);

			// check cm is not in coin_list
			let mut coin_list = CoinList::get();
			for e in coin_list.iter() {
				ensure!(
					*e != input.cm,
					Error::<T>::MantaCoinExist
				)
			}

			// add the new coin to the ledger
			coin_list.push(input.cm);

			// update the merkle root
			// let t: Vec<MantaCoin> = Vec::new();
			let new_state = priv_coin::merkle_root(hash_param, &coin_list);

			// write back to ledger storage
			Self::deposit_event(RawEvent::Minted(origin, amount));
			CoinList::put(coin_list);
			// let new_state = [0u8; 32];
			LedgerState::put(new_state);
			let old_pool_balance = PoolBalance::get();
			PoolBalance::put(old_pool_balance + amount);
			<Balances<T>>::insert(origin_account, origin_balance - amount);
		}


		/// Private Transfer
		#[weight = 0]
		fn manta_transfer(origin,
			merkle_root: [u8; 32],
			sender_data: [u8; 64],
			receiver_data: [u8; 80],
			proof: [u8; 192],
		) {

			let sender_data = SenderData::deserialize(sender_data.as_ref());
			let receiver_data = ReceiverData::deserialize(receiver_data.as_ref());
			ensure!(Self::is_init(), <Error<T>>::BasecoinNotInit);
			let origin = ensure_signed(origin)?;

			let hash_param = HashParam::deserialize(HASHPARAMBYTES.as_ref());
			let hash_param_checksum_local = hash_param.get_checksum();


			// get the parameter checksum from the ledger
			let hash_param_checksum = HashParamChecksum::get();
			ensure!(
				hash_param_checksum_local == hash_param_checksum,
				<Error<T>>::MintFail
			);
			// todo: checksum ZKP verification eky


			// check if sn_old already spent
			let mut sn_list = SNList::get();
			ensure!(!sn_list.contains(&sender_data.sn), <Error<T>>::MantaCoinSpent);
			sn_list.push(sender_data.sn);

			// update coin list
			let mut coin_list = CoinList::get();
			coin_list.push(receiver_data.cm);

			// get the verification key from the ledger
			let transfer_vk_bytes = TransferZKPKey::get();

			// get the ledger state from the ledger
			// and check the validity of the state
			let state = LedgerState::get();
			ensure!(state == merkle_root, <Error<T>>::InvalidLedgerState);
			let new_root = priv_coin::merkle_root(hash_param, &coin_list);

			// check validity of zkp
			ensure!(
				priv_coin::manta_verify_transfer_zkp(
					transfer_vk_bytes,
					proof,
					&sender_data,
					&receiver_data,
					merkle_root),
				<Error<T>>::ZKPFail,
			);

			// TODO: revisit replay attack here

			// update ledger storage
			let mut enc_value_list = EncValueList::get();
			enc_value_list.push(receiver_data.cipher);

			Self::deposit_event(RawEvent::PrivateTransferred(origin));
			CoinList::put(coin_list);
			SNList::put(sn_list);
			EncValueList::put(enc_value_list);
			LedgerState::put(new_root);
		}


		/// Reclaim
		#[weight = 0]
		fn reclaim(origin,
			amount: u64,
			merkle_root: [u8; 32],
			sender_data: [u8; 64],
			proof: [u8; 192],
		) {

			let sender_data = SenderData::deserialize(sender_data.as_ref());

			let origin = ensure_signed(origin)?;
			let origin_account = origin.clone();
			let origin_balance = <Balances<T>>::get(&origin);
			ensure!(Self::is_init(), <Error<T>>::BasecoinNotInit);

			let hash_param = HashParam::deserialize(HASHPARAMBYTES.as_ref());
			let hash_param_checksum_local = hash_param.get_checksum();


			// get the parameter checksum from the ledger
			let hash_param_checksum = HashParamChecksum::get();
			ensure!(
				hash_param_checksum_local == hash_param_checksum,
				<Error<T>>::MintFail
			);
			// todo: checksum ZKP verification eky

			// check the balance is greater than amount
			let mut pool = PoolBalance::get();
			ensure!(pool>=amount, <Error<T>>::PoolOverdrawn);
			pool -= amount;

			// check if sn_old already spent
			let mut sn_list = SNList::get();
			ensure!(!sn_list.contains(&sender_data.sn), <Error<T>>::MantaCoinSpent);
			sn_list.push(sender_data.sn);

			// get the coin list
			let coin_list = CoinList::get();

			// get the verification key from the ledger
			let reclaim_vk_bytes = ReclaimZKPKey::get();

			// get the ledger state from the ledger
			// and check the validity of the state
			let state = LedgerState::get();
			ensure!(state == merkle_root, <Error<T>>::InvalidLedgerState);
			let new_root = priv_coin::merkle_root(hash_param, &coin_list);

			// check validity of zkp
			ensure!(
				priv_coin::manta_verify_reclaim_zkp(
					reclaim_vk_bytes,
					amount,
					proof,
					&sender_data,
					merkle_root),
				<Error<T>>::ZKPFail,
			);

			// TODO: revisit replay attack here

			// update ledger storage
			Self::deposit_event(RawEvent::PrivateReclaimed(origin));
			CoinList::put(coin_list);
			SNList::put(sn_list);
			LedgerState::put(new_root);
			PoolBalance::put(pool);
			<Balances<T>>::insert(origin_account, origin_balance + amount);
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
		/// The assest was reclaimed
		PrivateReclaimed(AccountId),
	}
}

decl_error! {
	pub enum Error for Module<T: Config> {
		/// This token has already been initiated
		AlreadyInitialized,
		/// Transfer when not nitialized
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
		/// MantaCoin already spend
		MantaCoinSpent,
		/// ZKP verification failed
		ZKPFail,
		/// invalid ledger state
		InvalidLedgerState,
		/// Pool overdrawn
		PoolOverdrawn
	}
}

decl_storage! {
	trait Store for Module<T: Config> as Assets {
		/// The number of units of assets held by any given account.
		pub Balances: map hasher(blake2_128_concat) T::AccountId => u64;

		/// The total unit supply of the asset.
		pub TotalSupply get(fn total_supply): u64;

		/// Has this token been initialized (can only initiate once)
		pub Init get(fn is_init): bool;

		/// List of sns
		pub SNList get(fn sn_list): Vec<[u8; 32]>;

		/// List of Coins that has ever been created
		pub CoinList get(fn coin_list): Vec<[u8; 32]>;

		/// List of encrypted values
		pub EncValueList get(fn enc_value_list): Vec<[u8; 16]>;

		/// merkle root of list of commitments
		pub LedgerState get(fn legder_state): [u8; 32];

		/// the balance of minted coins
		pub PoolBalance get(fn pool_balance): u64;

		/// the seed of hash parameter
		pub HashParamChecksum get(fn hash_param_checksum): [u8; 32];

		/// the seed of commit parameter
		pub CommitParamChecksum get(fn commit_param_checksum): [u8; 32];

		/// verification key for zero-knowledge proof
		/// at the moment we are storing the whole serialized key
		/// in the blockchain storage.
		pub TransferZKPKey get(fn transfer_zkp_vk): Vec<u8>;

		/// verification key for zero-knowledge proof
		/// at the moment we are storing the whole serialized key
		/// in the blockchain storage.
		pub ReclaimZKPKey get(fn reclaim_zkp_vk): Vec<u8>;
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
