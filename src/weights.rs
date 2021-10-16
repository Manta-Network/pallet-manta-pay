
//! Autogenerated weights for `pallet_manta_pay`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2021-10-15, STEPS: `1`, REPEAT: 10, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: None, DB CACHE: 128

// Executed Command:
// target/release/manta
// benchmark
// --pallet
// pallet_manta_pay
// --extrinsic
// *
// --log
// warn
// --repeat
// 10
// --execution
// wasm
// --output
// weights.rs


#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use sp_std::marker::PhantomData;

/// Weight functions needed for pallet_manta_pay.
pub trait WeightInfo {
	fn init_asset() -> Weight;
	fn transfer_asset() -> Weight;
	fn mint_private_asset() -> Weight;
	fn private_transfer() -> Weight;
	fn reclaim() -> Weight;
}

/// Weight functions for pallet_manta_pay.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	// Storage: MantaPay TotalSupply (r:1 w:1)
	// Storage: MantaPay PoolBalance (r:0 w:1)
	// Storage: MantaPay Balances (r:0 w:1)
	fn init_asset() -> Weight {
		(20_000_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(1 as Weight))
			.saturating_add(T::DbWeight::get().writes(3 as Weight))
	}

	// Storage: MantaPay TotalSupply (r:1 w:0)
	// Storage: MantaPay Balances (r:2 w:2)
	fn transfer_asset() -> Weight {
		(27_000_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(3 as Weight))
			.saturating_add(T::DbWeight::get().writes(2 as Weight))
	}

	// Storage: MantaPay TotalSupply (r:1 w:0)
	// Storage: MantaPay Balances (r:1 w:0)
	// Storage: MantaPay UTXOSet (r:1 w:1)
	// Storage: MantaPay LedgerShardMetaData (r:1 w:1)
	// Storage: MantaPay PoolBalance (r:1 w:1)
	// Storage: MantaPay LedgerShardRoots (r:0 w:1)
	// Storage: MantaPay LedgerShards (r:0 w:1)
	fn mint_private_asset() -> Weight {
		(16_088_000_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(5 as Weight))
			.saturating_add(T::DbWeight::get().writes(5 as Weight))
	}

	// Storage: MantaPay VoidNumbers (r:2 w:2)
	// Storage: MantaPay LedgerShardRoots (r:2 w:2)
	// Storage: MantaPay UTXOSet (r:2 w:2)
	// Storage: MantaPay LedgerShardMetaData (r:2 w:2)
	// Storage: MantaPay LedgerShards (r:0 w:2)
	fn private_transfer() -> Weight {
		(65_023_000_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(8 as Weight))
			.saturating_add(T::DbWeight::get().writes(10 as Weight))
	}	

	// Storage: MantaPay TotalSupply (r:1 w:0)
	// Storage: MantaPay VoidNumbers (r:2 w:2)
	// Storage: MantaPay LedgerShardRoots (r:2 w:1)
	// Storage: MantaPay UTXOSet (r:1 w:1)
	// Storage: MantaPay LedgerShardMetaData (r:1 w:1)
	// Storage: MantaPay Balances (r:1 w:1)
	// Storage: MantaPay PoolBalance (r:1 w:1)
	// Storage: MantaPay LedgerShards (r:0 w:1)
	fn reclaim() -> Weight {
		(48_912_000_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(9 as Weight))
			.saturating_add(T::DbWeight::get().writes(8 as Weight))
	}
}

// For backwards compatibility and tests
impl WeightInfo for () {
	// Storage: MantaPay TotalSupply (r:1 w:1)
	// Storage: MantaPay PoolBalance (r:0 w:1)
	// Storage: MantaPay Balances (r:0 w:1)
	fn init_asset() -> Weight {
		(20_000_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(1 as Weight))
			.saturating_add(RocksDbWeight::get().writes(3 as Weight))
	}

	// Storage: MantaPay TotalSupply (r:1 w:0)
	// Storage: MantaPay Balances (r:2 w:2)
	fn transfer_asset() -> Weight {
		(27_000_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(3 as Weight))
			.saturating_add(RocksDbWeight::get().writes(2 as Weight))
	}

	// Storage: MantaPay TotalSupply (r:1 w:0)
	// Storage: MantaPay Balances (r:1 w:0)
	// Storage: MantaPay UTXOSet (r:1 w:1)
	// Storage: MantaPay LedgerShardMetaData (r:1 w:1)
	// Storage: MantaPay PoolBalance (r:1 w:1)
	// Storage: MantaPay LedgerShardRoots (r:0 w:1)
	// Storage: MantaPay LedgerShards (r:0 w:1)
	fn mint_private_asset() -> Weight {
		(16_088_000_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(5 as Weight))
			.saturating_add(RocksDbWeight::get().writes(5 as Weight))
	}

	// Storage: MantaPay VoidNumbers (r:2 w:2)
	// Storage: MantaPay LedgerShardRoots (r:2 w:2)
	// Storage: MantaPay UTXOSet (r:2 w:2)
	// Storage: MantaPay LedgerShardMetaData (r:2 w:2)
	// Storage: MantaPay LedgerShards (r:0 w:2)
	fn private_transfer() -> Weight {
		(65_023_000_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(8 as Weight))
			.saturating_add(RocksDbWeight::get().writes(10 as Weight))
	}	

	// Storage: MantaPay TotalSupply (r:1 w:0)
	// Storage: MantaPay VoidNumbers (r:2 w:2)
	// Storage: MantaPay LedgerShardRoots (r:2 w:1)
	// Storage: MantaPay UTXOSet (r:1 w:1)
	// Storage: MantaPay LedgerShardMetaData (r:1 w:1)
	// Storage: MantaPay Balances (r:1 w:1)
	// Storage: MantaPay PoolBalance (r:1 w:1)
	// Storage: MantaPay LedgerShards (r:0 w:1)
	fn reclaim() -> Weight {
		(48_912_000_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(9 as Weight))
			.saturating_add(RocksDbWeight::get().writes(8 as Weight))
	}
}