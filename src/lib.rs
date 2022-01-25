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

//! # MantaPay Module
//!
//! MantaPay is a Multi-Asset Shielded Payment protocol.
//!
//! _NB_: The design is similar though not the same with MASP (Multi-Asset Shielded Pool).
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
//!     that holds same number of private assets.
//! * **Private asset transfer:** The action of transferring certain number of private assets from
//!     two UTXOs to another two UTXOs.
//! * **Private asset reclaim:** The action of transferring certain number of private assets from
//!     two UTXOs to another UTXO, and converting the remaining private assets back to public
//!     assets.
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
//!     the function caller's account (`origin`) to a `target` account.
//! * `mint` - Converting an `amount` of units of fungible asset `id` from the caller
//!     to a private UTXO. (The caller does not need to be the owner of this UTXO)
//! * `private_transfer` - Transfer two input UTXOs into two output UTXOs. Require that 1) the input
//!     UTXOs are already in the ledger and are not spend before 2) the sum of private assets in
//!     input UTXOs matches that of the output UTXOs. The requirements are guaranteed via ZK proof.
//! * `reclaim` - Transfer two input UTXOs into one output UTXOs, and convert the remaining assets
//!     to the public assets. Require that 1) the input UTXOs are already in the ledger and are not
//!     spend before; 2) the sum of private assets in input UTXOs matches that of the output UTXO +
//!     the reclaimed amount. The requirements are guaranteed via ZK proof.
//!
//! Please refer to the [`Call`](./enum.Call.html) enum and its associated variants for
//! documentation on each function.
//!
//! ### Public Functions
//!
//! * `balance` - Get the asset balance of `who`.
//! * `total_supply` - Get the total supply of an asset `id`.
//!
//! Please refer to the [`Module`](./struct.Module.html) struct for details on publicly available
//! functions.
//!
//! ## Usage
//!
//! The following example shows how to use the Assets module in your runtime by exposing public
//! functions to:
//!
//! * Initiate the fungible asset for a token distribution event (airdrop).
//! * Query the fungible asset holding balance of an account.
//! * Query the total supply of a fungible asset that has been issued.
//! * Query the total number of private fungible asset that has been minted and not reclaimed.
//!
//! ### Prerequisites
//!
//! Import the Assets module and types and derive your runtime's configuration traits from the
//! Assets module trait.
//!
//! ## Related Modules
//!
//! * [`System`](../frame_system/index.html)
//! * [`Support`](../frame_support/index.html)

#![cfg_attr(not(feature = "std"), no_std)]

use core::marker::PhantomData;
use frame_support::ensure;
use manta_accounting::{
	asset,
	transfer::{
		canonical::TransferShape, AccountBalance, InvalidSinkAccount, InvalidSourceAccount, Proof,
		ReceiverLedger, ReceiverPostError, ReceiverPostingKey, SenderLedger, SenderPostError,
		SenderPostingKey, SinkPostingKey, SourcePostingKey, TransferLedger,
		TransferLedgerSuperPostingKey, TransferPostError,
	},
};
use manta_crypto::{
	constraint::ProofSystem,
	merkle_tree::{self, forest::Configuration as _},
};
use manta_pay::config;
use manta_util::codec::Decode as _;
use scale_codec::{Decode, Encode};
use sp_std::prelude::*;
use types::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod test;

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmark;

#[allow(clippy::unnecessary_cast)] // NOTE: This file is auto-generated.
pub mod weights;

pub use pallet::*;
pub use weights::WeightInfo;

/// Type Definitions for Protocol Structures
pub mod types {
	use super::*;

	/// Asset Id Type
	pub type AssetId = asset::AssetIdType;

	/// Asset Value Type
	pub type AssetValue = asset::AssetValueType;

	/// Asset
	#[derive(Clone, Copy, Debug, Decode, Default, Encode, Eq, Hash, Ord, PartialEq, PartialOrd)]
	pub struct Asset {
		/// Asset Id
		pub id: AssetId,

		/// Asset Value
		pub value: AssetValue,
	}

	impl Asset {
		/// Builds a new [`Asset`] from `id` and `value`.
		#[inline]
		pub fn new(id: AssetId, value: AssetValue) -> Self {
			Self { id, value }
		}
	}

	/// Encrypted Note
	#[derive(Clone, Debug, Decode, Encode, Eq, Hash, PartialEq)]
	pub struct EncryptedNote {
		/// Ciphertext
		pub ciphertext: config::Ciphertext,

		/// Ephemeral Public Key
		pub ephemeral_public_key: config::PublicKey,
	}

	impl Default for EncryptedNote {
		#[inline]
		fn default() -> Self {
			Self {
				ciphertext: [0; 36],
				ephemeral_public_key: Default::default(),
			}
		}
	}

	impl From<config::EncryptedNote> for EncryptedNote {
		#[inline]
		fn from(note: config::EncryptedNote) -> Self {
			Self {
				ciphertext: note.ciphertext,
				ephemeral_public_key: note.ephemeral_public_key,
			}
		}
	}

	impl From<EncryptedNote> for config::EncryptedNote {
		#[inline]
		fn from(note: EncryptedNote) -> Self {
			Self {
				ciphertext: note.ciphertext,
				ephemeral_public_key: note.ephemeral_public_key,
			}
		}
	}

	/// Sender Post
	#[derive(Clone, Debug, Decode, Encode, Eq, Hash, PartialEq)]
	pub struct SenderPost {
		/// UTXO Set Output
		pub utxo_set_output: config::UtxoSetOutput,

		/// Void Number
		pub void_number: config::VoidNumber,
	}

	impl From<config::SenderPost> for SenderPost {
		#[inline]
		fn from(post: config::SenderPost) -> Self {
			Self {
				utxo_set_output: post.utxo_set_output,
				void_number: post.void_number,
			}
		}
	}

	impl From<SenderPost> for config::SenderPost {
		#[inline]
		fn from(post: SenderPost) -> Self {
			Self {
				utxo_set_output: post.utxo_set_output,
				void_number: post.void_number,
			}
		}
	}

	/// Receiver Post
	#[derive(Clone, Debug, Decode, Encode, Eq, Hash, PartialEq)]
	pub struct ReceiverPost {
		/// Unspent Transaction Output
		pub utxo: config::Utxo,

		/// Encrypted Note
		pub note: EncryptedNote,
	}

	impl From<config::ReceiverPost> for ReceiverPost {
		#[inline]
		fn from(post: config::ReceiverPost) -> Self {
			Self {
				utxo: post.utxo,
				note: post.note.into(),
			}
		}
	}

	impl From<ReceiverPost> for config::ReceiverPost {
		#[inline]
		fn from(post: ReceiverPost) -> Self {
			Self {
				utxo: post.utxo,
				note: post.note.into(),
			}
		}
	}

	/// Transfer Post
	#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
	pub struct TransferPost {
		/// Asset Id
		pub asset_id: Option<AssetId>,

		/// Sources
		pub sources: Vec<AssetValue>,

		/// Sender Posts
		pub sender_posts: Vec<SenderPost>,

		/// Receiver Posts
		pub receiver_posts: Vec<ReceiverPost>,

		/// Sinks
		pub sinks: Vec<AssetValue>,

		/// Validity Proof
		pub validity_proof: config::Proof,
	}

	impl From<config::TransferPost> for TransferPost {
		#[inline]
		fn from(post: config::TransferPost) -> Self {
			Self {
				asset_id: post.asset_id.map(|id| id.0),
				sources: post.sources.into_iter().map(|s| s.0).collect(),
				sender_posts: post.sender_posts.into_iter().map(Into::into).collect(),
				receiver_posts: post.receiver_posts.into_iter().map(Into::into).collect(),
				sinks: post.sinks.into_iter().map(|s| s.0).collect(),
				validity_proof: post.validity_proof,
			}
		}
	}

	impl From<TransferPost> for config::TransferPost {
		#[inline]
		fn from(post: TransferPost) -> Self {
			Self {
				asset_id: post.asset_id.map(asset::AssetId),
				sources: post.sources.into_iter().map(asset::AssetValue).collect(),
				sender_posts: post.sender_posts.into_iter().map(Into::into).collect(),
				receiver_posts: post.receiver_posts.into_iter().map(Into::into).collect(),
				sinks: post.sinks.into_iter().map(asset::AssetValue).collect(),
				validity_proof: post.validity_proof,
			}
		}
	}

	/// Leaf Digest Type
	pub type LeafDigest = merkle_tree::LeafDigest<config::MerkleTreeConfiguration>;

	/// Inner Digest Type
	pub type InnerDigest = merkle_tree::InnerDigest<config::MerkleTreeConfiguration>;

	/// Merkle Tree Current Path
	#[derive(Clone, Debug, Decode, Default, Encode, Eq, PartialEq)]
	pub struct CurrentPath {
		/// Sibling Digest
		pub sibling_digest: LeafDigest,

		/// Leaf Index
		pub leaf_index: u32,

		/// Inner Path
		pub inner_path: Vec<InnerDigest>,
	}

	impl From<merkle_tree::CurrentPath<config::MerkleTreeConfiguration>> for CurrentPath {
		#[inline]
		fn from(path: merkle_tree::CurrentPath<config::MerkleTreeConfiguration>) -> Self {
			Self {
				sibling_digest: path.sibling_digest,
				leaf_index: path.inner_path.leaf_index.0 as u32,
				inner_path: path.inner_path.path,
			}
		}
	}

	impl From<CurrentPath> for merkle_tree::CurrentPath<config::MerkleTreeConfiguration> {
		#[inline]
		fn from(path: CurrentPath) -> Self {
			Self::new(
				path.sibling_digest,
				(path.leaf_index as usize).into(),
				path.inner_path,
			)
		}
	}

	/// UTXO Merkle Tree
	#[derive(Clone, Debug, Decode, Default, Encode, Eq, PartialEq)]
	pub struct UtxoMerkleTree {
		/// Current Leaf Digest
		pub leaf_digest: Option<LeafDigest>,

		/// Current Path
		pub current_path: CurrentPath,
	}
}

/// MantaPay Pallet
#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use sp_runtime::traits::StaticLookup;

	///
	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	/// The module configuration trait.
	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// The overarching event type.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

		/// Weight information for extrinsics in this pallet.
		type WeightInfo: WeightInfo;
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	///
	#[pallet::storage]
	pub(super) type Balances<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		Blake2_128Concat,
		AssetId,
		AssetValue,
		ValueQuery,
	>;

	///
	#[pallet::storage]
	pub(super) type TotalSupply<T: Config> =
		StorageMap<_, Blake2_128Concat, AssetId, AssetValue, ValueQuery>;

	///
	#[pallet::storage]
	pub(super) type Shards<T: Config> =
		StorageDoubleMap<_, Identity, u8, Identity, u64, (config::Utxo, EncryptedNote), ValueQuery>;

	///
	#[pallet::storage]
	pub(super) type ShardTrees<T: Config> = StorageMap<_, Identity, u8, UtxoMerkleTree, ValueQuery>;

	///
	#[pallet::storage]
	pub(super) type UtxoSetOutputs<T: Config> =
		StorageMap<_, Identity, config::UtxoSetOutput, (), ValueQuery>;

	///
	#[pallet::storage]
	pub(super) type UtxoSet<T: Config> = StorageMap<_, Identity, config::Utxo, (), ValueQuery>;

	///
	#[pallet::storage]
	pub(super) type VoidNumberSet<T: Config> =
		StorageMap<_, Identity, config::VoidNumber, (), ValueQuery>;

	///
	#[pallet::storage]
	pub(super) type VoidNumberSetInsertionOrder<T: Config> =
		StorageMap<_, Identity, u64, config::VoidNumber, ValueQuery>;

	///
	#[pallet::storage]
	pub(super) type VoidNumberSetSize<T: Config> = StorageValue<_, u64, ValueQuery>;

	///
	#[pallet::genesis_config]
	pub struct GenesisConfig<T: Config> {
		pub owner: T::AccountId,
		pub assets: sp_std::collections::btree_set::BTreeSet<(AssetId, AssetValue)>,
	}

	#[cfg(feature = "std")]
	impl<T: Config> Default for GenesisConfig<T> {
		#[inline]
		fn default() -> Self {
			GenesisConfig {
				owner: Default::default(),
				assets: Default::default(),
			}
		}
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
		#[inline]
		fn build(&self) {
			for (id, value) in &self.assets {
				Pallet::<T>::init_asset(&self.owner, *id, *value);
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
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
			asset: Asset,
		) -> DispatchResultWithPostInfo {
			let origin = ensure_signed(origin)?;
			let target = T::Lookup::lookup(target)?;
			ensure!(
				TotalSupply::<T>::contains_key(&asset.id),
				Error::<T>::UninitializedSupply
			);
			let origin_balance = Balances::<T>::get(&origin, asset.id);
			ensure!(asset.value > 0, Error::<T>::ZeroTransfer);
			ensure!(origin_balance >= asset.value, Error::<T>::BalanceLow);
			Balances::<T>::mutate(&origin, asset.id, |balance| *balance -= asset.value);
			Balances::<T>::mutate(&target, asset.id, |balance| *balance += asset.value);
			Self::deposit_event(Event::Transfer {
				asset,
				source: origin,
				sink: target,
			});
			Ok(().into())
		}

		///
		#[pallet::weight(T::WeightInfo::mint_private_asset())]
		pub fn mint(origin: OriginFor<T>, post: TransferPost) -> DispatchResultWithPostInfo {
			let origin = ensure_signed(origin)?;
			let mut ledger = Self::ledger();
			Self::deposit_event(
				config::TransferPost::from(post)
					.validate(vec![origin], vec![], &ledger)
					.map_err(Error::<T>::from)?
					.post(&(), &mut ledger)
					.convert(None),
			);
			Ok(().into())
		}

		///
		#[pallet::weight(T::WeightInfo::private_transfer())]
		pub fn private_transfer(
			origin: OriginFor<T>,
			post: TransferPost,
		) -> DispatchResultWithPostInfo {
			let origin = ensure_signed(origin)?;
			let mut ledger = Self::ledger();
			Self::deposit_event(
				config::TransferPost::from(post)
					.validate(vec![], vec![], &ledger)
					.map_err(Error::<T>::from)?
					.post(&(), &mut ledger)
					.convert(Some(origin)),
			);
			Ok(().into())
		}

		///
		#[pallet::weight(T::WeightInfo::reclaim())]
		pub fn reclaim(origin: OriginFor<T>, post: TransferPost) -> DispatchResultWithPostInfo {
			let origin = ensure_signed(origin)?;
			let mut ledger = Self::ledger();
			Self::deposit_event(
				config::TransferPost::from(post)
					.validate(vec![], vec![origin], &ledger)
					.map_err(Error::<T>::from)?
					.post(&(), &mut ledger)
					.convert(None),
			);
			Ok(().into())
		}
	}

	/// MantaPay Event
	#[pallet::event]
	#[pallet::generate_deposit(fn deposit_event)]
	#[pallet::metadata(T::AccountId = "AccountId")]
	pub enum Event<T: Config> {
		/// Transfer Event
		Transfer {
			/// Asset Transfered
			asset: Asset,

			/// Source Account
			source: T::AccountId,

			/// Sink Account
			sink: T::AccountId,
		},

		/// Mint Event
		Mint {
			/// Asset Minted
			asset: Asset,

			/// Source Account
			source: T::AccountId,
		},

		/// Private Transfer Event
		PrivateTransfer {
			/// Origin Account
			origin: T::AccountId,
		},

		/// Reclaim Event
		Reclaim {
			/// Asset Reclaimed
			asset: Asset,

			/// Sink Account
			sink: T::AccountId,
		},
	}

	/// MantaPay Error
	#[pallet::error]
	pub enum Error<T> {
		/// Uninitialized Supply
		///
		/// Supply of the given Asset Id has not yet been initialized.
		UninitializedSupply,

		/// Zero Transfer
		///
		/// Public transfers cannot include amounts equal to zero.
		ZeroTransfer,

		/// Balance Low
		///
		/// Attempted to withdraw from balance which was smaller than the withdrawl amount.
		BalanceLow,

		/// Invalid Shape
		///
		/// The transfer had an invalid shape.
		InvalidShape,

		/// Asset Spent
		///
		/// An asset present in this transfer has already been spent.
		AssetSpent,

		/// Invalid UTXO Set Output
		///
		/// The sender was constructed on an invalid version of the ledger state.
		InvalidUtxoSetOutput,

		/// Asset Registered
		///
		/// An asset present in this transfer has already been registered to the ledger.
		AssetRegistered,

		/// Duplicate Spend
		///
		/// There were multiple spend entries for the same underlying asset in this transfer.
		DuplicateSpend,

		/// Duplicate Register
		///
		/// There were multiple register entries for the same underlying asset in this transfer.
		DuplicateRegister,

		/// Invalid Proof
		///
		/// The submitted proof did not pass validation, or errored during validation.
		InvalidProof,
	}

	impl<T> From<InvalidSourceAccount<T::AccountId>> for Error<T>
	where
		T: Config,
	{
		#[inline]
		fn from(err: InvalidSourceAccount<T::AccountId>) -> Self {
			match err.balance {
				AccountBalance::Known(_) => Self::BalanceLow,
				AccountBalance::UnknownAccount => {
					unreachable!("Accounts are checked before reaching this point.")
				}
			}
		}
	}

	impl<T> From<InvalidSinkAccount<T::AccountId>> for Error<T>
	where
		T: Config,
	{
		#[inline]
		fn from(err: InvalidSinkAccount<T::AccountId>) -> Self {
			let _ = err;
			unimplemented!("Accounts are checked before reaching this point.")
		}
	}

	impl<T> From<SenderPostError> for Error<T> {
		#[inline]
		fn from(err: SenderPostError) -> Self {
			match err {
				SenderPostError::AssetSpent => Self::AssetSpent,
				SenderPostError::InvalidUtxoSetOutput => Self::InvalidUtxoSetOutput,
			}
		}
	}

	impl<T> From<ReceiverPostError> for Error<T> {
		#[inline]
		fn from(err: ReceiverPostError) -> Self {
			match err {
				ReceiverPostError::AssetRegistered => Self::AssetRegistered,
			}
		}
	}

	impl<T> From<TransferPostError<T::AccountId>> for Error<T>
	where
		T: Config,
	{
		#[inline]
		fn from(err: TransferPostError<T::AccountId>) -> Self {
			match err {
				TransferPostError::InvalidShape => Self::InvalidShape,
				TransferPostError::InvalidSourceAccount(err) => err.into(),
				TransferPostError::InvalidSinkAccount(err) => err.into(),
				TransferPostError::Sender(err) => err.into(),
				TransferPostError::Receiver(err) => err.into(),
				TransferPostError::DuplicateSpend => Self::DuplicateSpend,
				TransferPostError::DuplicateRegister => Self::DuplicateRegister,
				TransferPostError::InvalidProof => Self::InvalidProof,
			}
		}
	}
}

impl<T> Pallet<T>
where
	T: Config,
{
	/// Initialize `asset_id` with a supply of `total`, giving control to `owner`.
	#[inline]
	fn init_asset(owner: &T::AccountId, asset_id: AssetId, total: AssetValue) {
		TotalSupply::<T>::insert(asset_id, total);
		Balances::<T>::insert(owner, asset_id, total);
	}

	/// Returns the balance of `account` for the asset with the given `id`.
	#[inline]
	pub fn balance(account: T::AccountId, id: AssetId) -> AssetValue {
		Balances::<T>::get(account, id)
	}

	/// Returns the total supply of the asset with the given `id`.
	#[inline]
	pub fn total_supply(id: AssetId) -> AssetValue {
		TotalSupply::<T>::get(id)
	}

	/// Returns the ledger implementation for this pallet.
	#[inline]
	fn ledger() -> Ledger<T> {
		Ledger(PhantomData)
	}
}

/// Preprocessed Event
pub enum PreprocessedEvent<T>
where
	T: Config,
{
	/// Mint Event
	Mint {
		/// Asset Minted
		asset: Asset,

		/// Source Account
		source: T::AccountId,
	},

	/// Private Transfer Event
	PrivateTransfer,

	/// Reclaim Event
	Reclaim {
		/// Asset Reclaimed
		asset: Asset,

		/// Sink Account
		sink: T::AccountId,
	},
}

impl<T> PreprocessedEvent<T>
where
	T: Config,
{
	/// Converts a [`PreprocessedEvent`] with into an [`Event`] using the given `origin` for
	/// [`PreprocessedEvent::PrivateTransfer`].
	#[inline]
	pub fn convert(self, origin: Option<T::AccountId>) -> Event<T> {
		match self {
			Self::Mint { asset, source } => Event::Mint { asset, source },
			Self::PrivateTransfer => Event::PrivateTransfer {
				origin: origin.unwrap(),
			},
			Self::Reclaim { asset, sink } => Event::Reclaim { asset, sink },
		}
	}
}

/// Ledger
pub struct Ledger<T>(PhantomData<T>)
where
	T: Config;

/// Wrap Type
#[derive(Clone, Copy)]
pub struct Wrap<T>(T);

impl<T> AsRef<T> for Wrap<T> {
	#[inline]
	fn as_ref(&self) -> &T {
		&self.0
	}
}

/// Wrap Pair Type
#[derive(Clone, Copy)]
pub struct WrapPair<L, R>(L, R);

impl<L, R> AsRef<R> for WrapPair<L, R> {
	#[inline]
	fn as_ref(&self) -> &R {
		&self.1
	}
}

impl<T> SenderLedger<config::Config> for Ledger<T>
where
	T: Config,
{
	type ValidVoidNumber = Wrap<config::VoidNumber>;
	type ValidUtxoSetOutput = Wrap<config::UtxoSetOutput>;
	type SuperPostingKey = (Wrap<()>, ());

	#[inline]
	fn is_unspent(&self, void_number: config::VoidNumber) -> Option<Self::ValidVoidNumber> {
		if VoidNumberSet::<T>::contains_key(&void_number) {
			None
		} else {
			Some(Wrap(void_number))
		}
	}

	#[inline]
	fn has_matching_utxo_set_output(
		&self,
		output: config::UtxoSetOutput,
	) -> Option<Self::ValidUtxoSetOutput> {
		if UtxoSetOutputs::<T>::contains_key(output) {
			return Some(Wrap(output));
		}
		None
	}

	#[inline]
	fn spend(
		&mut self,
		utxo_set_output: Self::ValidUtxoSetOutput,
		void_number: Self::ValidVoidNumber,
		super_key: &Self::SuperPostingKey,
	) {
		let _ = (utxo_set_output, super_key);
		let index = VoidNumberSetSize::<T>::get();
		VoidNumberSet::<T>::insert(void_number.0, ());
		VoidNumberSetInsertionOrder::<T>::insert(index, void_number.0);
		VoidNumberSetSize::<T>::set(index + 1);
	}
}

impl<T> ReceiverLedger<config::Config> for Ledger<T>
where
	T: Config,
{
	type ValidUtxo = Wrap<config::Utxo>;
	type SuperPostingKey = (Wrap<()>, ());

	#[inline]
	fn is_not_registered(&self, utxo: config::Utxo) -> Option<Self::ValidUtxo> {
		if UtxoSet::<T>::contains_key(&utxo) {
			None
		} else {
			Some(Wrap(utxo))
		}
	}

	#[inline]
	fn register(
		&mut self,
		utxo: Self::ValidUtxo,
		note: config::EncryptedNote,
		super_key: &Self::SuperPostingKey,
	) {
		// TODO: Add `register_all` command to amortize cost of getting and setting `ShardTrees``.

		let _ = super_key;

		let parameters = merkle_tree::Parameters::decode(
			manta_sdk::pay::testnet::parameters::UTXO_SET_PARAMETERS,
		)
		.expect("Unable to decode the Merkle Tree Parameters.");

		let shard_index = config::MerkleTreeConfiguration::tree_index(&utxo.0);

		let mut tree = ShardTrees::<T>::get(shard_index);

		let next_root = {
			let mut current_path = core::mem::take(&mut tree.current_path).into();
			let next_root = merkle_tree::single_path::raw::insert(
				&parameters,
				&mut tree.leaf_digest,
				&mut current_path,
				utxo.0,
			)
			.expect("If this errors, then we have run out of Merkle Tree capacity.");
			tree.current_path = current_path.into();
			next_root
		};

		let next_index = tree.current_path.leaf_index as u64;

		ShardTrees::<T>::insert(shard_index, tree);

		UtxoSet::<T>::insert(utxo.0, ());
		UtxoSetOutputs::<T>::insert(next_root, ());
		Shards::<T>::insert(shard_index, next_index, (utxo.0, EncryptedNote::from(note)));
	}
}

impl<T> TransferLedger<config::Config> for Ledger<T>
where
	T: Config,
{
	type AccountId = T::AccountId;
	type Event = PreprocessedEvent<T>;
	type ValidSourceAccount = WrapPair<Self::AccountId, asset::AssetValue>;
	type ValidSinkAccount = WrapPair<Self::AccountId, asset::AssetValue>;
	type ValidProof = Wrap<()>;
	type SuperPostingKey = ();

	#[inline]
	fn check_source_accounts<I>(
		&self,
		asset_id: asset::AssetId,
		sources: I,
	) -> Result<Vec<Self::ValidSourceAccount>, InvalidSourceAccount<Self::AccountId>>
	where
		I: Iterator<Item = (Self::AccountId, asset::AssetValue)>,
	{
		// NOTE: Existence of accounts is type-checked so we only need check account balances.
		sources
			.map(move |(account_id, withdraw)| {
				match Balances::<T>::try_get(&account_id, asset_id.0) {
					Ok(balance) => {
						// FIXME: Check if balance would withdraw more than existential deposit.
						if balance >= withdraw.0 {
							Ok(WrapPair(account_id, withdraw))
						} else {
							Err(InvalidSourceAccount {
								account_id,
								balance: AccountBalance::Known(asset::AssetValue(balance)),
								withdraw,
							})
						}
					}
					_ => Err(InvalidSourceAccount {
						account_id,
						balance: AccountBalance::Known(asset::AssetValue(0)),
						withdraw,
					}),
				}
			})
			.collect()
	}

	#[inline]
	fn check_sink_accounts<I>(
		&self,
		sinks: I,
	) -> Result<Vec<Self::ValidSinkAccount>, InvalidSinkAccount<Self::AccountId>>
	where
		I: Iterator<Item = (Self::AccountId, asset::AssetValue)>,
	{
		// NOTE: Existence of accounts is type-checked so we don't need to do anything here, just
		//		 pass the data forward.
		Ok(sinks
			.map(move |(account_id, deposit)| WrapPair(account_id, deposit))
			.collect())
	}

	#[inline]
	fn is_valid(
		&self,
		asset_id: Option<asset::AssetId>,
		sources: &[SourcePostingKey<config::Config, Self>],
		senders: &[SenderPostingKey<config::Config, Self>],
		receivers: &[ReceiverPostingKey<config::Config, Self>],
		sinks: &[SinkPostingKey<config::Config, Self>],
		proof: Proof<config::Config>,
	) -> Option<(Self::ValidProof, Self::Event)> {
		let (mut verifying_context, event) = match TransferShape::select(
			asset_id.is_some(),
			sources.len(),
			senders.len(),
			receivers.len(),
			sinks.len(),
		)? {
			TransferShape::Mint => (
				manta_sdk::pay::testnet::verifying::MINT,
				PreprocessedEvent::Mint::<T> {
					asset: Asset::new(asset_id.unwrap().0, (sources[0].1).0),
					source: sources[0].0.clone(),
				},
			),
			TransferShape::PrivateTransfer => (
				manta_sdk::pay::testnet::verifying::PRIVATE_TRANSFER,
				PreprocessedEvent::PrivateTransfer::<T>,
			),
			TransferShape::Reclaim => (
				manta_sdk::pay::testnet::verifying::RECLAIM,
				PreprocessedEvent::Reclaim::<T> {
					asset: Asset::new(asset_id.unwrap().0, (sinks[0].1).0),
					sink: sinks[0].0.clone(),
				},
			),
		};
		config::ProofSystem::verify(
			&manta_accounting::transfer::TransferPostingKey::generate_proof_input(
				asset_id, sources, senders, receivers, sinks,
			),
			&proof,
			&config::VerifyingContext::decode(&mut verifying_context)
				.expect("Unable to decode the verifying context."),
		)
		.ok()?
		.then(move || (Wrap(()), event))
	}

	#[inline]
	fn update_public_balances(
		&mut self,
		asset_id: asset::AssetId,
		sources: Vec<SourcePostingKey<config::Config, Self>>,
		sinks: Vec<SinkPostingKey<config::Config, Self>>,
		proof: Self::ValidProof,
		super_key: &TransferLedgerSuperPostingKey<config::Config, Self>,
	) {
		let _ = (proof, super_key);
		for WrapPair(account_id, withdraw) in sources {
			Balances::<T>::mutate(&account_id, asset_id.0, |balance| *balance -= withdraw.0);
		}
		for WrapPair(account_id, deposit) in sinks {
			Balances::<T>::mutate(&account_id, asset_id.0, |balance| *balance += deposit.0);
		}
	}
}
