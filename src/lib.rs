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

//! # MantaPay Module
//!
//! MantaPay is a Multi-Asset Shielded Payment protocol.
//! The design is similar though not the same with MASP (Multi-Asset Shielded Pool).
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

#[cfg(test)]
mod mock;

#[cfg(test)]
mod test;

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmark;

#[allow(clippy::unnecessary_cast)] // NOTE: This file is auto-generated.
pub mod weights;

pub use weights::WeightInfo;

use frame_support::{dispatch::DispatchResult, ensure};
use manta_asset::{shard_index, AssetBalance, AssetId, MantaRandomValue, SanityCheck, UTXO};
use manta_crypto::{
	merkle_tree::LedgerMerkleTree, try_commitment_parameters, try_default_leaf_hash,
	try_leaf_parameters, try_two_to_one_parameters, LeafHashParam, MantaCrypto,
	MantaEciesCiphertext, MantaZKPVerifier, TwoToOneHashParam,
};
use manta_data::{MintData, PrivateTransferData, ReclaimData, ShardMetaData};
use sp_runtime::DispatchError;
use sp_std::prelude::*;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use manta_crypto::{RECLAIM_VK, TRANSFER_VK};
	use sp_runtime::traits::StaticLookup;

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	// NOTE: if the visibility of trait store is private but you want to make it available
	// in super, then use `pub(super)` or `pub(crate)` to make it available in crate.
	pub struct Pallet<T>(_);

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

	/// The number of units of assets held by any given account.
	#[pallet::storage]
	pub(super) type Balances<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		Blake2_128Concat,
		AssetId,
		AssetBalance,
		ValueQuery,
	>;

	/// The total unit supply of the asset.
	/// If 0, then this asset is not initialized.
	#[pallet::storage]
	pub(super) type TotalSupply<T: Config> =
		StorageMap<_, Blake2_128Concat, AssetId, AssetBalance, ValueQuery>;

	/// (shard_index, index_within_shard) -> payload
	#[pallet::storage]
	pub(super) type LedgerShards<T: Config> =
		StorageDoubleMap<_, Identity, u8, Identity, u64, (UTXO, MantaEciesCiphertext), ValueQuery>;

	/// store of ShardMetaData
	/// i.e. LedgerShardMetaData.get(0) is the 1st shard's next available index and serialized_path
	#[pallet::storage]
	pub(super) type LedgerShardMetaData<T: Config> =
		StorageMap<_, Identity, u8, ShardMetaData, ValueQuery>;

	/// store of shard roots
	#[pallet::storage]
	pub(super) type LedgerShardRoots<T: Config> =
		StorageMap<_, Identity, u8, MantaRandomValue, ValueQuery>;

	/// The set of UTXOs
	#[pallet::storage]
	pub(super) type UTXOSet<T: Config> = StorageMap<_, Twox64Concat, UTXO, bool, ValueQuery>;

	/// The set of void numbers (similar to the nullifiers in ZCash)
	#[pallet::storage]
	pub(super) type VoidNumbers<T: Config> =
		StorageMap<_, Twox64Concat, MantaRandomValue, bool, ValueQuery>;

	/// The balance of all minted private coins for this asset_id.
	#[pallet::storage]
	pub(super) type PoolBalance<T: Config> =
		StorageMap<_, Twox64Concat, AssetId, AssetBalance, ValueQuery>;

	#[pallet::genesis_config]
	pub struct GenesisConfig<T: Config> {
		pub owner: T::AccountId,
		pub assets: Vec<(AssetId, AssetBalance)>,
	}

	#[cfg(feature = "std")]
	impl<T: Config> Default for GenesisConfig<T> {
		fn default() -> Self {
			GenesisConfig {
				owner: Default::default(),
				assets: Default::default(),
			}
		}
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
		fn build(&self) {
			for (asset, supply) in &self.assets {
				Pallet::<T>::init_asset(&self.owner, *asset, *supply);
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Issue a new class of fungible assets. There are, and will only ever be, `total`
		/// such assets and they'll all belong to the `origin` initially. It will have an
		/// identifier `AssetId` instance: this will be specified in the `Issued` event.

		/// Move some assets from one holder to another.
		///
		/// # <weight>
		/// - `O(1)`
		/// - 1 static lookup
		/// - 2 storage mutations (codec `O(1)`).
		/// - 1 event.
		/// # </weight>
		#[pallet::weight(T::WeightInfo::transfer_asset())]
		pub fn transfer_asset(
			origin: OriginFor<T>,
			target: <T::Lookup as StaticLookup>::Source,
			asset_id: AssetId,
			amount: AssetBalance,
		) -> DispatchResultWithPostInfo {
			let origin = ensure_signed(origin)?;
			// Make sure the base coin is initialized
			ensure!(
				TotalSupply::<T>::contains_key(&asset_id),
				Error::<T>::BasecoinNotInit
			);

			let origin_balance = Balances::<T>::get(&origin, asset_id);
			let target = T::Lookup::lookup(target)?;
			ensure!(amount > 0, Error::<T>::AmountZero);
			ensure!(origin_balance >= amount, Error::<T>::BalanceLow);
			Balances::<T>::mutate(&origin, asset_id, |balance| *balance -= amount);
			Balances::<T>::mutate(&target, asset_id, |balance| *balance += amount);

			Self::deposit_event(Event::Transferred(asset_id, origin, target, amount));
			Ok(().into())
		}

		/// Mint private asset
		#[pallet::weight(T::WeightInfo::mint_private_asset())]
		pub fn mint_private_asset(
			origin: OriginFor<T>,
			mint_data: MintData,
		) -> DispatchResultWithPostInfo {
			let origin = ensure_signed(origin)?;

			// asset id must exist
			let asset_id = mint_data.asset_id;
			ensure!(
				TotalSupply::<T>::contains_key(&mint_data.asset_id),
				<Error<T>>::BasecoinNotInit
			);

			// get the original balance
			let origin_balance = Balances::<T>::get(&origin, asset_id);
			ensure!(origin_balance >= mint_data.value, Error::<T>::BalanceLow);

			// get paramters for merkle tree, commitment
			let leaf_param = try_leaf_parameters()
				.map_err::<DispatchError, _>(|_| Error::<T>::ParamFail.into())?;

			let two_to_one_param = try_two_to_one_parameters()
				.map_err::<DispatchError, _>(|_| Error::<T>::ParamFail.into())?;

			let commit_param = try_commitment_parameters()
				.map_err::<DispatchError, _>(|_| Error::<T>::ParamFail.into())?;

			// check the validity of the commitment
			// i.e. check that `cm = COMM(asset_id || v || k, s)`.
			let res = mint_data
				.sanity(&commit_param)
				.map_err::<DispatchError, _>(|_| Error::<T>::MintFail.into())?;

			ensure!(res, Error::<T>::MintFail);

			// add commitment and encrypted note
			// update merkle root
			Pallet::<T>::insert_commitments(
				&leaf_param,
				&two_to_one_param,
				vec![(mint_data.cm, mint_data.encrypted_note)],
			)
			.map_err::<DispatchError, _>(|_| Error::<T>::LedgerUpdateFail.into())?;

			// update public balance and pool balance
			Balances::<T>::mutate(&origin, asset_id, |balance| *balance -= mint_data.value);
			PoolBalance::<T>::mutate(asset_id, |balance| *balance += mint_data.value);
			Self::deposit_event(Event::<T>::Minted(asset_id, origin, mint_data.value));
			Ok(().into())
		}

		/// Manta's private transfer function that moves values from two
		/// sender's private tokens into two receiver tokens. A proof is required to
		/// make sure that this transaction is valid.
		/// Neither the values nor the identities is leaked during this process.
		#[pallet::weight(T::WeightInfo::private_transfer())]
		pub fn private_transfer(
			origin: OriginFor<T>,
			private_transfer_data: PrivateTransferData,
		) -> DispatchResultWithPostInfo {
			let origin = ensure_signed(origin)?;

			// get paramters for merkle tree, commitment
			let leaf_param = try_leaf_parameters()
				.map_err::<DispatchError, _>(|_| Error::<T>::ParamFail.into())?;

			let two_to_one_param = try_two_to_one_parameters()
				.map_err::<DispatchError, _>(|_| Error::<T>::ParamFail.into())?;

			let senders = [
				private_transfer_data.sender_0,
				private_transfer_data.sender_1,
			];

			// Check that both void numbers are unique.
			ensure!(
				senders[0].void_number != senders[1].void_number,
				Error::<T>::MantaCoinSpent
			);

			// Check if void numbers are already spent and verfiy sender's merkle root.
			for sender in senders {
				ensure!(
					!VoidNumbers::<T>::contains_key(sender.void_number),
					Error::<T>::MantaCoinSpent
				);
				ensure!(
					LedgerShardRoots::<T>::get(sender.shard_index) == sender.root,
					Error::<T>::InvalidLedgerState
				);
			}

			// verify ZKP
			let transfer_vk = TRANSFER_VK;
			ensure!(
				private_transfer_data.verify(&transfer_vk),
				Error::<T>::ZkpVerificationFail
			);

			// add commitment and encrypted note
			// update merkle root
			let coins = vec![
				(
					private_transfer_data.receiver_0.cm,
					private_transfer_data.receiver_0.encrypted_note,
				),
				(
					private_transfer_data.receiver_1.cm,
					private_transfer_data.receiver_1.encrypted_note,
				),
			];

			// Check that both utxos are unique.
			ensure!(coins[0].0 != coins[1].0, Error::<T>::MantaCoinExist);

			Pallet::<T>::insert_commitments(&leaf_param, &two_to_one_param, coins)
				.map_err::<DispatchError, _>(|_| Error::<T>::LedgerUpdateFail.into())?;

			// insert void numbers
			for sender in senders {
				VoidNumbers::<T>::insert(sender.void_number, true);
			}

			// deposit the event then update the storage
			Self::deposit_event(Event::PrivateTransferred(origin));

			Ok(().into())
		}

		/// Manta's reclaim function that moves values from two
		/// sender's private tokens into a receiver public account, and a private token.
		/// A proof is required to
		/// make sure that this transaction is valid.
		/// Neither the values nor the identities is leaked during this process;
		/// except for the reclaimed amount.
		#[pallet::weight(T::WeightInfo::reclaim())]
		pub fn reclaim(
			origin: OriginFor<T>,
			reclaim_data: ReclaimData,
		) -> DispatchResultWithPostInfo {
			// make sure it is properly signed
			let origin = ensure_signed(origin)?;

			// make sure the asset_id exists
			let asset_id = reclaim_data.asset_id;
			ensure!(
				TotalSupply::<T>::contains_key(asset_id),
				Error::<T>::BasecoinNotInit
			);

			// get the params of hashes
			let leaf_param = try_leaf_parameters()
				.map_err::<DispatchError, _>(|_| Error::<T>::ParamFail.into())?;

			let two_to_one_param = try_two_to_one_parameters()
				.map_err::<DispatchError, _>(|_| Error::<T>::ParamFail.into())?;

			let senders = [reclaim_data.sender_0, reclaim_data.sender_1];

			// Check that both void numbers are unique.
			ensure!(
				senders[0].void_number != senders[1].void_number,
				Error::<T>::MantaCoinSpent
			);

			// Check if void numbers are already spent and verfiy sender's merkle root.
			for sender in senders {
				ensure!(
					!VoidNumbers::<T>::contains_key(sender.void_number),
					Error::<T>::MantaCoinSpent
				);
				ensure!(
					LedgerShardRoots::<T>::get(sender.shard_index) == sender.root,
					Error::<T>::InvalidLedgerState
				)
			}

			// verify zkp
			let reclaim_vk = RECLAIM_VK;
			ensure!(
				reclaim_data.verify(&reclaim_vk),
				Error::<T>::ZkpVerificationFail
			);

			// add commitment and encrypted note
			// update merkle root
			Pallet::<T>::insert_commitments(
				&leaf_param,
				&two_to_one_param,
				vec![(
					reclaim_data.receiver.cm,
					reclaim_data.receiver.encrypted_note,
				)],
			)
			.map_err::<DispatchError, _>(|_| Error::<T>::LedgerUpdateFail.into())?;

			// insert void numbers
			for sender in senders {
				VoidNumbers::<T>::insert(sender.void_number, true);
			}

			// mutate balance and update the pool balance
			Balances::<T>::mutate(&origin, asset_id, |balance| {
				*balance += reclaim_data.reclaim_value
			});
			PoolBalance::<T>::mutate(asset_id, |balance| *balance -= reclaim_data.reclaim_value);

			// register the event
			Self::deposit_event(Event::Reclaimed(
				asset_id,
				origin,
				reclaim_data.reclaim_value,
			));
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
		Reclaimed(AssetId, T::AccountId, AssetBalance),
	}

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

pub use pallet::*;

impl<T: Config> Pallet<T> {
	/// Returns the balance of `account` for the asset with the given `id`.
	#[inline]
	pub fn balance(account: T::AccountId, id: AssetId) -> AssetBalance {
		Balances::<T>::get(account, id)
	}

	/// Returns the total supply of the asset with the given `id`.
	#[inline]
	pub fn total_supply(id: AssetId) -> AssetBalance {
		TotalSupply::<T>::get(id)
	}

	/// Returns `true` if `utxo` is stored in the ledger.
	#[inline]
	fn utxo_exists(utxo: UTXO) -> bool {
		UTXOSet::<T>::contains_key(utxo)
	}

	/// Init testnet asset
	#[inline]
	fn init_asset(owner: &T::AccountId, asset_id: AssetId, total: AssetBalance) {
		// initialize the asset with `total` number of supplies
		// the total number of private asset (pool balance) remain 0
		// the assets is credit to the sender's account
		PoolBalance::<T>::insert(asset_id, 0);
		TotalSupply::<T>::insert(asset_id, total);
		Balances::<T>::insert(owner, asset_id, total);
	}

	/// Returns the `commitments` split into the shards they will be inserted into.
	#[inline]
	fn split_commitments_by_shard(
		commitments: Vec<(UTXO, MantaEciesCiphertext)>,
	) -> Result<Vec<ShardCommitments>, Error<T>> {
		let mut shards = Vec::<ShardCommitments>::new();
		for cm in commitments {
			ensure!(!Self::utxo_exists(cm.0), Error::<T>::LedgerUpdateFail);
			let index = shard_index(cm.0);
			match shards.iter_mut().find(move |s| s.index == index) {
				Some(shard) => shard.commitments.push(cm),
				_ => shards.push(ShardCommitments {
					index,
					commitments: vec![cm],
				}),
			}
		}
		// TODO: Loop over each shard and emit error if shard would overflow.
		Ok(shards)
	}

	/// Loads the `ShardUpdatingData` from the ledger for the shard at `shard_index`, returning
	/// a default value if the shard is empty.
	#[inline]
	fn load_shard_updating_data(shard_index: u8) -> Result<ShardUpdatingData, Error<T>> {
		Ok(match LedgerShardMetaData::<T>::try_get(shard_index) {
			Ok(metadata) => ShardUpdatingData {
				is_empty: false,
				current_utxo: LedgerShards::<T>::get(shard_index, metadata.current_index).0,
				leaf_sibling: Self::get_sibling_utxo(metadata.current_index, || {
					LedgerShards::<T>::get(shard_index, metadata.current_index - 1).0
				})?,
				metadata,
			},
			_ => Default::default(),
		})
	}

	/// Generates the data required on updating the ledger for the given `shard`.
	#[inline]
	fn generate_shard_update(
		leaf_param: &LeafHashParam,
		two_to_one_param: &TwoToOneHashParam,
		shard: ShardCommitments,
	) -> Result<ShardUpdate, Error<T>> {
		let ShardUpdatingData {
			mut is_empty,
			mut current_utxo,
			mut leaf_sibling,
			metadata: ShardMetaData {
				mut current_index,
				mut current_auth_path,
			},
		} = Self::load_shard_updating_data(shard.index)?;
		let mut update = ShardUpdate {
			shard,
			root: Default::default(),
			metadata: ShardMetaData {
				current_index: current_index.wrapping_sub(is_empty as u64),
				current_auth_path,
			},
		};
		for (cm, _) in &update.shard.commitments {
			let (path, root) = <MantaCrypto as LedgerMerkleTree>::next_path_and_root(
				leaf_param,
				two_to_one_param,
				current_index as usize,
				is_empty,
				&current_utxo,
				&leaf_sibling,
				&current_auth_path,
				cm,
			)
			.map_err(move |_| Error::<T>::LedgerUpdateFail)?;
			if !is_empty {
				current_index += 1;
			}
			is_empty = false;
			leaf_sibling = Self::get_sibling_utxo(current_index, move || current_utxo)?;
			current_utxo = *cm;
			current_auth_path = path;
			update.root = root;
		}
		update.metadata.current_auth_path = current_auth_path;
		Ok(update)
	}

	/// Inserts the new UTXOs and encrypted notes into the map, updating the merkle root and path.
	#[inline]
	fn insert_commitments(
		leaf_param: &LeafHashParam,
		two_to_one_param: &TwoToOneHashParam,
		commitments: Vec<(UTXO, MantaEciesCiphertext)>,
	) -> DispatchResult {
		if commitments.is_empty() {
			return Ok(());
		}
		let updates = Self::split_commitments_by_shard(commitments)?
			.into_iter()
			.map(|shard| Self::generate_shard_update(leaf_param, two_to_one_param, shard))
			.collect::<Result<Vec<_>, Error<T>>>()?;
		for ShardUpdate {
			shard,
			root,
			mut metadata,
		} in updates
		{
			for cm in shard.commitments {
				metadata.current_index = metadata.current_index.wrapping_add(1);
				LedgerShards::<T>::insert(shard.index, metadata.current_index, cm);
				UTXOSet::<T>::insert(cm.0, true);
			}
			LedgerShardMetaData::<T>::insert(shard.index, metadata);
			LedgerShardRoots::<T>::insert(shard.index, root);
		}
		Ok(())
	}

	/// Returns the sibling of the node at the given `index`, using `previous` to get the node to
	/// the left of `index` if it is the sibling.
	#[inline]
	fn get_sibling_utxo<F>(index: u64, previous: F) -> Result<UTXO, Error<T>>
	where
		F: FnOnce() -> UTXO,
	{
		if index % 2 == 0 {
			try_default_leaf_hash().map_err(move |_| Error::<T>::LedgerUpdateFail)
		} else {
			Ok(previous())
		}
	}
}

/// Shard Commitments
struct ShardCommitments {
	/// Index of the target shard
	index: u8,

	/// Commitments to insert
	commitments: Vec<(UTXO, MantaEciesCiphertext)>,
}

/// Shard Updating Data
struct ShardUpdatingData {
	/// Empty Shard Flag
	is_empty: bool,

	/// Current UTXO
	current_utxo: UTXO,

	/// Sibling to the Current UTXO
	leaf_sibling: UTXO,

	/// Shard Metadata
	metadata: ShardMetaData,
}

impl Default for ShardUpdatingData {
	#[inline]
	fn default() -> Self {
		Self {
			is_empty: true,
			current_utxo: Default::default(),
			leaf_sibling: Default::default(),
			metadata: Default::default(),
		}
	}
}

/// Shard Update
struct ShardUpdate {
	/// Shard Index and Commitments to Insert
	shard: ShardCommitments,

	/// New Root
	root: MantaRandomValue,

	/// New Metadata
	metadata: ShardMetaData,
}
