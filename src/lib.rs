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

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	// NOTE: if the visibility of trait store is private but you want to make it available
	// in super, then use `pub(super)` or `pub(crate)` to make it available in crate.
	pub struct Pallet<T>(_);
	// pub struct Pallet<T, I = ()>(PhantomData<T>); // for instantiable pallet

	/// The module configuration trait.
	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// The overarching event type.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

		/// Weight information for extrinsics in this pallet.
		type WeightInfo: WeightInfo;
	}

	// BlockNumberFor imported from frame_system::pallet_prelude::*
	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Issue a new class of fungible assets. There are, and will only ever be, `total`
		/// such assets and they'll all belong to the `origin` initially. It will have an
		/// identifier `AssetId` instance: this will be specified in the `Issued` event.
		/// # <weight>
		/// - `O(1)`
		/// - 1 storage mutation (codec `O(1)`).
		/// - 2 storage writes (codec `O(1)`).
		/// - 1 event.
		/// # </weight>
		#[pallet::weight(T::WeightInfo::init_asset())]
		pub(super) fn init_asset(
			origin: OriginFor<T>,
			asset_id: AssetId,
			total: AssetBalance,
		) -> DispatchResultWithPostInfo {
			Ok(().into())
		}

		/// Move some assets from one holder to another.
		///
		/// # <weight>
		/// - `O(1)`
		/// - 1 static lookup
		/// - 2 storage mutations (codec `O(1)`).
		/// - 1 event.
		/// # </weight>
		#[pallet::weight(T::WeightInfo::transfer_asset())]
		pub(super) fn transfer_asset(
			origin: OriginFor<T>,
			target: <T::Lookup as StaticLookup>::Source,
			asset_id: AssetId,
			amount: AssetBalance,
		) -> DispatchResultWithPostInfo {
			Ok(().into())
		}

		/// Given an amount, and relevant data, mint the token to the ledger
		#[pallet::weight(T::WeightInfo::mint_private_asset())]
		pub(super) fn mint_private_asset(
			origin: OriginFor<T>,
			payload: MintPayload,
		) -> DispatchResultWithPostInfo {
			Ok(().into())
		}

		/// Manta's private transfer function that moves values from two
		/// sender's private tokens into two receiver tokens. A proof is required to
		/// make sure that this transaction is valid.
		/// Neither the values nor the identities is leaked during this process.
		#[pallet::weight(T::WeightInfo::private_transfer())]
		pub(super) fn private_transfer(
			origin: OriginFor<T>,
			payload: PrivateTransferPayload,
		) -> DispatchResultWithPostInfo {
			Ok(().into())
		}

		/// Manta's reclaim function that moves values from two
		/// sender's private tokens into a receiver public account, and a private token.
		/// A proof is required to
		/// make sure that this transaction is valid.
		/// Neither the values nor the identities is leaked during this process;
		/// except for the reclaimed amount.
		/// At the moment, the reclaimed amount goes directly to `origin` account.
		/// __TODO__: shall we use a different receiver rather than `origin`?
		#[pallet::weight(T::WeightInfo::reclaim())]
		pub(super) fn reclaim(
			origin: OriginFor<T>,
			payload: ReclaimPayload,
		) -> DispatchResultWithPostInfo {
			Ok(().into())
		}
	}

	#[pallet::event]
	#[pallet::generate_deposit(fn deposit_event)]
	#[pallet::metadata(T::AccountId = "AccountId")] // This is how you overwrite metadata of fields. This string value is the metadata you want to have.
	pub enum Event<T: Config> {
		/// The asset was issued. \[asset_id, owner, total_supply\]
		Issued(AssetId, T::AccountId, AssetBalance),
		/// The asset was transferred. \[from, to, amount\]
		Transferred(AssetId, T::AccountId, T::AccountId, AssetBalance),
		/// The asset was minted to private
		Minted(AssetId, T::AccountId, AssetBalance),
		/// Private transfer
		PrivateTransferred(T::AccountId),
		/// The assets was reclaimed
		PrivateReclaimed(AssetId, T::AccountId, AssetBalance),
	}

	type RawEvent<T> = Event<T>;

	/// Error messages.
	#[pallet::error]
	pub enum Error<T> {
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

	/// The number of units of assets held by any given account.
	#[pallet::storage]
	pub type Balances<T: Config> =
		StorageDoubleMap<_, Blake2_128Concat, T::AccountId, Blake2_128Concat, u64, u64, ValueQuery>;

	/// The total unit supply of the asset.
	/// If 0, then this asset is not initialized.
	#[pallet::storage]
	pub type TotalSupply<T: Config> = StorageMap<_, Blake2_128Concat, u64, u64, ValueQuery>;

	/// List of _void number_s.
	/// A void number is also known as a `serial number` or `nullifier` in other protocols.
	/// Each coin has a unique void number, and if this number is revealed,
	/// the coin is voided.
	/// The ledger maintains a list of all void numbers.
	#[pallet::storage]
	#[pallet::getter(fn vn_list)]
	pub type VNList<T: Config> = StorageValue<_, Vec<[u8; 32]>, ValueQuery>;

	/// List of Coins that has ever been created.
	/// We employ a sharding system to host all the coins
	/// for better concurrency.
	#[pallet::storage]
	#[pallet::getter(fn coin_shards)]
	pub type CoinShards<T: Config> = StorageValue<_, MantaPrivateAssetLedger, ValueQuery>;

	/// List of encrypted values.
	#[pallet::storage]
	#[pallet::getter(fn enc_value_list)]
	pub type EncValueList<T: Config> = StorageValue<_, Vec<[u8; 16]>, ValueQuery>;

	/// The balance of all minted coins for this asset_id.
	#[pallet::storage]
	pub type PoolBalance<T: Config> = StorageMap<_, Blake2_128Concat, u64, u64, ValueQuery>;

	/// The checksum of hash parameter.
	#[pallet::storage]
	#[pallet::getter(fn hash_param_checksum)]
	pub type HashParamChecksum<T: Config> = StorageValue<_, [u8; 32], ValueQuery>;

	/// The checksum of commitment parameter.
	#[pallet::storage]
	#[pallet::getter(fn commit_param_checksum)]
	pub type CommitParamChecksum<T: Config> = StorageValue<_, [u8; 32], ValueQuery>;

	/// The verification key for zero-knowledge proof for transfer protocol.
	/// At the moment we are storing the whole serialized key
	/// in the blockchain storage.
	#[pallet::storage]
	#[pallet::getter(fn transfer_zkp_key_checksum)]
	pub type TransferZKPKeyChecksum<T: Config> = StorageValue<_, [u8; 32], ValueQuery>;

	/// The verification key for zero-knowledge proof for reclaim protocol.
	/// At the moment we are storing the whole serialized key
	/// in the blockchain storage.
	#[pallet::storage]
	#[pallet::getter(fn reclaim_zkp_key_checksum)]
	pub type ReclaimZKPKeyChecksum<T: Config> = StorageValue<_, [u8; 32], ValueQuery>;
}
