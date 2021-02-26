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

extern crate ark_crypto_primitives;
extern crate ark_ed_on_bls12_381;
extern crate ark_groth16;
extern crate ark_r1cs_std;
extern crate ark_relations;
extern crate ark_serialize;
extern crate ark_std;
extern crate generic_array;
extern crate rand_chacha;
extern crate x25519_dalek;

// pub mod dap_setup;
mod dh;
pub mod forfeit;
pub mod manta_token;
pub mod param;
pub mod priv_coin;
pub mod transfer;

#[cfg(test)]
pub mod test;

use ark_std::vec::Vec;
use frame_support::{decl_error, decl_event, decl_module, decl_storage, ensure};
use frame_system::ensure_signed;
use manta_token::MantaCoin;
use param::{COMMITPARAMSEED, FORFEITVKBYTES, HASHPARAMSEED, TRANSFERVKBYTES};
use sp_runtime::traits::{StaticLookup, Zero};

/// The module configuration trait.
pub trait Trait: frame_system::Trait {
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
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

            // for now we hard code the seeds as:
            //  * hash parameter seed: [1u8; 32]
            //  * commitment parameter seed: [2u8; 32]
            // We may want to pass those two in for `init`
            let hash_param_seed = HASHPARAMSEED;
            let commit_param_seed = COMMITPARAMSEED;

            // push the ZKP verification key to the ledger storage
            //
            // NOTE:
            //    this is is generated via
            //      let zkp_key = priv_coin::manta_zkp_key_gen(&hash_param_seed, &commit_param_seed);
            //
            // for prototype, we use this function to generate the ZKP verification key
            // for product we should use a MPC protocol to build the ZKP verification key
            // and then depoly that vk
            //
            TransferZKPKey::put(TRANSFERVKBYTES.to_vec());
            ForfeitZKPKey::put(FORFEITVKBYTES.to_vec());

            CoinList::put(Vec::<MantaCoin>::new());
            LedgerState::put([4u8; 32]);
            PoolBalance::put(0);
            SNList::put(Vec::<[u8; 32]>::new());
            EncValueList::put(Vec::<[u8; 16]>::new());
            <Balances<T>>::insert(&origin, total);
            <TotalSupply>::put(total);
            Self::deposit_event(RawEvent::Issued(origin, total));
            Init::put(true);
            HashParamSeed::put(hash_param_seed);
            CommitParamSeed::put(commit_param_seed);
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
            k: [u8; 32],
            s: [u8; 32],
            cm: [u8; 32]
        ) {
            // get the original balance
            ensure!(Self::is_init(), <Error<T>>::BasecoinNotInit);
            let origin = ensure_signed(origin)?;
            let origin_account = origin.clone();
            ensure!(!amount.is_zero(), Error::<T>::AmountZero);
            let origin_balance = <Balances<T>>::get(&origin_account);
            ensure!(origin_balance >= amount, Error::<T>::BalanceLow);

            // get the parameter seeds from the ledger
            let hash_param_seed = HashParamSeed::get();
            let commit_param_seed = CommitParamSeed::get();

            // check the validity of the commitment
            let payload = [amount.to_le_bytes().as_ref(), k.as_ref()].concat();
            ensure!(
                priv_coin::comm_open(&commit_param_seed, &s, &payload, &cm),
                <Error<T>>::MintFail
            );

            // check cm is not in coin_list
            let mut coin_list = CoinList::get();
            for e in coin_list.iter() {
                ensure!(
                    e.cm_bytes != cm,
                    Error::<T>::MantaCoinExist
                )
            }

            // add the new coin to the ledger
            let coin = MantaCoin {
                cm_bytes: cm,
            };
            coin_list.push(coin);

            // update the merkle root
            // let t: Vec<MantaCoin> = Vec::new();
            let new_state = priv_coin::merkle_root(&hash_param_seed, &coin_list);

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
            sn_old: [u8; 32],
            k_old: [u8; 32],
            k_new: [u8; 32],
            cm_new: [u8; 32],
            enc_amount: [u8; 16],
            proof: [u8; 192]
        ) {

            ensure!(Self::is_init(), <Error<T>>::BasecoinNotInit);
            let origin = ensure_signed(origin)?;

            // check if sn_old already spent
            let mut sn_list = SNList::get();
            ensure!(!sn_list.contains(&sn_old), <Error<T>>::MantaCoinSpent);
            sn_list.push(sn_old);

            // update coin list
            let mut coin_list = CoinList::get();
            let coin_new = MantaCoin{
                cm_bytes: cm_new,
            };
            coin_list.push(coin_new);

            // get the verification key from the ledger
            let transfer_vk_bytes = TransferZKPKey::get();

            // get the ledger state from the ledger
            // and check the validity of the state
            let state = LedgerState::get();
            ensure!(state == merkle_root, <Error<T>>::InvalidLedgerState);
            let new_root = priv_coin::merkle_root(&HASHPARAMSEED, &coin_list);

            // check validity of zkp
            ensure!(
                priv_coin::manta_verify_transfer_zkp(transfer_vk_bytes, proof, sn_old, k_old, k_new, cm_new, merkle_root),
                <Error<T>>::ZKPFail,
            );

            // TODO: revisit replay attack here

            // update ledger storage
            let mut enc_value_list = EncValueList::get();
            enc_value_list.push(enc_amount);

            Self::deposit_event(RawEvent::PrivateTransferred(origin));
            CoinList::put(coin_list);
            SNList::put(sn_list);
            EncValueList::put(enc_value_list);
            LedgerState::put(new_root);
        }


        /// Forfeit
        #[weight = 0]
        fn forfeit(origin,
            amount: u64,
            merkle_root: [u8; 32],
            sn_old: [u8; 32],
            k_old: [u8; 32],
            proof: [u8; 192]
        ) {

            ensure!(Self::is_init(), <Error<T>>::BasecoinNotInit);
            let origin = ensure_signed(origin)?;

            // check the balance is greater than amount
            let mut pool = PoolBalance::get();
            ensure!(pool>=amount, <Error<T>>::PoolOverdrawn);
            pool -= amount;

            // check if sn_old already spent
            let mut sn_list = SNList::get();
            ensure!(!sn_list.contains(&sn_old), <Error<T>>::MantaCoinSpent);
            sn_list.push(sn_old);

            // get the coin list
            let coin_list = CoinList::get();

            // get the verification key from the ledger
            let forfeit_vk_bytes = ForfeitZKPKey::get();

            // get the ledger state from the ledger
            // and check the validity of the state
            let state = LedgerState::get();
            ensure!(state == merkle_root, <Error<T>>::InvalidLedgerState);
            let new_root = priv_coin::merkle_root(&HASHPARAMSEED, &coin_list);

            // check validity of zkp
            ensure!(
                priv_coin::manta_verify_forfeit_zkp(forfeit_vk_bytes, amount, proof, sn_old, k_old, merkle_root),
                <Error<T>>::ZKPFail,
            );

            // TODO: revisit replay attack here

            // update ledger storage
            // FIXME: change RawEvent here
            Self::deposit_event(RawEvent::PrivateTransferred(origin));
            CoinList::put(coin_list);
            SNList::put(sn_list);
            LedgerState::put(new_root);
            PoolBalance::put(pool);
        }

    }
}

decl_event! {
    pub enum Event<T> where
        <T as frame_system::Trait>::AccountId,
    {
        /// The asset was issued. \[owner, total_supply\]
        Issued(AccountId, u64),
        /// The asset was transferred. \[from, to, amount\]
        Transferred(AccountId, AccountId, u64),
        /// The asset was minted to private
        Minted(AccountId, u64),
        /// Private transfer
        PrivateTransferred(AccountId),
    }
}

decl_error! {
    pub enum Error for Module<T: Trait> {
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
    trait Store for Module<T: Trait> as Assets {
        /// The number of units of assets held by any given account.
        pub Balances: map hasher(blake2_128_concat) T::AccountId => u64;

        /// The total unit supply of the asset.
        pub TotalSupply get(fn total_supply): u64;

        /// Has this token been initialized (can only initiate once)
        pub Init get(fn is_init): bool;

        /// List of sns
        pub SNList get(fn sn_list): Vec<[u8; 32]>;

        /// List of Coins that has ever been created
        pub CoinList get(fn coin_list): Vec<MantaCoin>;

        /// List of encrypted values
        pub EncValueList get(fn enc_value_list): Vec<[u8; 16]>;

        /// merkle root of list of commitments
        pub LedgerState get(fn legder_state): [u8; 32];

        /// the balance of minted coins
        pub PoolBalance get(fn pool_balance): u64;

        /// the seed of hash parameter
        pub HashParamSeed get(fn hash_param_seed): [u8; 32];

        /// the seed of commit parameter
        pub CommitParamSeed get(fn commit_param_seed): [u8; 32];

        /// verification key for zero-knowledge proof
        /// at the moment we are storing the whole serialized key
        /// in the blockchain storage.
        pub TransferZKPKey get(fn transfer_zkp_vk): Vec<u8>;

        /// verification key for zero-knowledge proof
        /// at the moment we are storing the whole serialized key
        /// in the blockchain storage.
        pub ForfeitZKPKey get(fn forfeit_zkp_vk): Vec<u8>;
    }
}

// The main implementation block for the module.
impl<T: Trait> Module<T> {
    // Public immutables

    /// Get the asset `id` balance of `who`.
    pub fn balance(who: T::AccountId) -> u64 {
        <Balances<T>>::get(who)
    }
}
