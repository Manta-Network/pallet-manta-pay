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
//! * `mint_private_asset` - Converting an `amount` of units of fungible asset `id` from the caller
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

use codec::{Decode, Encode};
use core::marker::PhantomData;
use frame_support::{ensure, Deserialize, Serialize};
use manta_accounting::{
	asset,
	transfer::{
		self, AccountBalance, InvalidSinkAccount, InvalidSourceAccount, Proof, ReceiverLedger,
		ReceiverPostError, ReceiverPostingKey, SenderLedger, SenderPostError, SenderPostingKey,
		SinkPostingKey, SourcePostingKey, TransferLedger, TransferLedgerSuperPostingKey,
		TransferPostError,
	},
};
use manta_pay::config;
use sp_std::prelude::*;
use types::*;

/* TODO:
#[cfg(test)]
mod mock;

#[cfg(test)]
mod test;

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmark;
*/

#[allow(clippy::unnecessary_cast)] // NOTE: This file is auto-generated.
pub mod weights;

pub use pallet::*;
pub use weights::WeightInfo;

///
pub mod types {
	use super::*;

	///
	pub type AssetId = asset::AssetIdType;

	///
	pub type AssetValue = asset::AssetValueType;

	///
	#[derive(
		Clone,
		Debug,
		Decode,
		Default,
		Deserialize,
		Encode,
		Eq,
		Hash,
		Ord,
		PartialEq,
		PartialOrd,
		Serialize,
	)]
	pub struct Asset {
		///
		pub id: AssetId,

		///
		pub value: AssetValue,
	}

	///
	pub type Utxo = [u8; 32];

	///
	pub type UtxoSetOutput = [u8; 32];

	///
	pub type VoidNumber = [u8; 32];

	///
	#[derive(Clone, Debug, Decode, Default, Encode, Eq, Hash, PartialEq)]
	pub struct EncryptedNote {
		///
		pub ciphertext: [u8; 32],

		///
		pub ephemeral_public_key: [u8; 32],
	}

	///
	#[derive(Clone, Debug, Decode, Default, Encode, Eq, Hash, PartialEq)]
	pub struct SenderPost {
		/// UTXO Set Output
		pub utxo_set_output: UtxoSetOutput,

		/// Void Number
		pub void_number: VoidNumber,
	}

	///
	#[derive(Clone, Debug, Decode, Default, Encode, Eq, Hash, PartialEq)]
	pub struct ReceiverPost {
		/// Unspent Transaction Output
		pub utxo: Utxo,

		/// Encrypted Note
		pub note: EncryptedNote,
	}

	///
	#[derive(Clone, Debug, Decode, Default, Encode, Eq, Hash, PartialEq)]
	pub struct TransferPost {
		///
		pub asset_id: Option<AssetId>,

		///
		pub sources: Vec<AssetValue>,

		///
		pub senders: Vec<SenderPost>,

		///
		pub receivers: Vec<ReceiverPost>,

		///
		pub sinks: Vec<AssetValue>,
	}
}

/// MantaPay Pallet
#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use sp_runtime::traits::StaticLookup;
	use sp_std::collections::btree_set::BTreeSet;

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
		StorageDoubleMap<_, Identity, u8, Identity, u64, (Utxo, EncryptedNote), ValueQuery>;

	/* TODO:
	///
	#[pallet::storage]
	pub(super) type LedgerShardMetaData<T: Config> =
		StorageMap<_, Identity, u8, ShardMetaData, ValueQuery>;
	*/

	///
	#[pallet::storage]
	pub(super) type ShardOutputs<T: Config> =
		StorageMap<_, Identity, u8, UtxoSetOutput, ValueQuery>;

	///
	#[pallet::storage]
	pub(super) type UtxoSet<T: Config> = StorageMap<_, Identity, Utxo, (), ValueQuery>;

	///
	#[pallet::storage]
	pub(super) type VoidNumberSet<T: Config> = StorageMap<_, Identity, VoidNumber, (), ValueQuery>;

	///
	#[pallet::storage]
	pub(super) type VoidNumberSetInsertionOrder<T: Config> =
		StorageMap<_, Identity, u64, VoidNumber, ValueQuery>;

	///
	#[pallet::storage]
	pub(super) type VoidNumberSetSize<T: Config> = StorageValue<_, u64, ValueQuery>;

	///
	#[pallet::genesis_config]
	pub struct GenesisConfig<T: Config> {
		pub owner: T::AccountId,
		pub assets: BTreeSet<Asset>,
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
		#[inline]
		fn build(&self) {
			for asset in &self.assets {
				Pallet::<T>::init_asset(&self.owner, asset.id, asset.value);
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
			// TODO: move this to ledger abstraction.
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
		pub fn mint_private_asset(
			origin: OriginFor<T>,
			post: TransferPost,
		) -> DispatchResultWithPostInfo {
			let origin = ensure_signed(origin)?;
			/*
			let mut ledger = Self::ledger();
			Self::deposit_event(
				post.validate(vec![origin], vec![], &ledger)
					.map_err(Error::<T>::from)?
					.post(&(), &mut ledger),
			);
			*/
			Ok(().into())
		}

		///
		#[pallet::weight(T::WeightInfo::private_transfer())]
		pub fn private_transfer(
			origin: OriginFor<T>,
			post: TransferPost,
		) -> DispatchResultWithPostInfo {
			let origin = ensure_signed(origin)?;
			/*
			let mut ledger = Self::ledger();
			Self::deposit_event(
				post.validate(vec![], vec![], &ledger)
					.map_err(Error::<T>::from)?
					.post(&(), &mut ledger),
			);
			*/
			Ok(().into())
		}

		///
		#[pallet::weight(T::WeightInfo::reclaim())]
		pub fn reclaim(origin: OriginFor<T>, post: TransferPost) -> DispatchResultWithPostInfo {
			let origin = ensure_signed(origin)?;
			/*
			let mut ledger = Self::ledger();
			Self::deposit_event(
				post.validate(vec![], vec![origin], &ledger)
					.map_err(Error::<T>::from)?
					.post(&(), &mut ledger),
			);
			*/
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
				AccountBalance::Known(_) => {
					// TODO: Maybe we can give a more informative error.
					Self::BalanceLow
				}
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
	type ValidUtxoSetOutput = Wrap<transfer::UtxoSetOutput<config::Config>>;
	type SuperPostingKey = (Wrap<()>, ());

	#[inline]
	fn is_unspent(&self, void_number: config::VoidNumber) -> Option<Self::ValidVoidNumber> {
		/* TODO:
		if VoidNumberSet::<T>::contains_key(&void_number) {
			None
		} else {
			Some(Wrap(void_number))
		}
		*/
		todo!()
	}

	#[inline]
	fn has_matching_utxo_set_output(
		&self,
		output: transfer::UtxoSetOutput<config::Config>,
	) -> Option<Self::ValidUtxoSetOutput> {
		/* TODO:
		for tree in self.utxo_forest.forest.as_ref() {
			if tree.root() == &output {
				return Some(Wrap(output));
			}
		}
		None
		*/
		todo!()
	}

	#[inline]
	fn spend(
		&mut self,
		utxo_set_output: Self::ValidUtxoSetOutput,
		void_number: Self::ValidVoidNumber,
		super_key: &Self::SuperPostingKey,
	) {
		/* TODO:
		let _ = (utxo_set_output, super_key);
		let index = VoidNumberSetSize::<T>::get();
		VoidNumberSet::<T>::insert(void_number.0, ());
		VoidNumberSetInsertionOrder::<T>::insert(index, void_number.0);
		VoidNumberSetSize::<T>::set(index + 1);
		*/
		todo!()
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
		/* TODO:
		if UtxoSet::<T>::contains_key(&utxo) {
			None
		} else {
			Some(Wrap(utxo))
		}
		*/
		todo!()
	}

	#[inline]
	fn register(
		&mut self,
		utxo: Self::ValidUtxo,
		note: config::EncryptedNote,
		super_key: &Self::SuperPostingKey,
	) {
		/* TODO:
		use manta_crypto::merkle_tree::forest::Configuration;
		let _ = super_key;
		let shard_index = config::MerkleTreeConfiguration::tree_index(&utxo.0);
		let metadata = LedgerShardMetaData::<T>::get(shard_index);
		LedgerShards::<T>::insert(shard_index, metadata.next_index, (utxo.0, note));
		// TODO: update metadata, path, etc.
		*/
		todo!()
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
		/*
		let (verifying_context, event) = match TransferShape::select(
			asset_id.is_some(),
			sources.len(),
			senders.len(),
			receivers.len(),
			sinks.len(),
		)? {
			TransferShape::Mint => {
				let event = PreprocessedEvent::Mint {
					asset: Asset {
						id: asset_id.unwrap().0,
						value: (sources[0].1).0,
					},
					source: sources[0].0,
				};
				todo!()
			}
			TransferShape::PrivateTransfer => {
				let event = PreprocessedEvent::PrivateTransfer;
				todo!()
			}
			TransferShape::Reclaim => {
				let event = PreprocessedEvent::Reclaim {
					asset: Asset {
						id: asset_id.unwrap().0,
						value: (sinks[0].1).0,
					},
					sink: sinks[0].0,
				};
				todo!()
			}
		};
		*/

		/* TODO:
		ProofSystem::verify(
			&TransferPostingKey::generate_proof_input(asset_id, sources, senders, receivers, sinks),
			&proof,
			verifying_context,
		)
		.ok()?
		.then(move || (Wrap(()), event))
		*/
		todo!()
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
