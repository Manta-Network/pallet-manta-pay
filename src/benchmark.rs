//! manta-dap pallet benchmarking.

#![cfg(feature = "runtime-benchmarks")]

use super::*;
use data_encoding::BASE64;
use frame_benchmarking::{account, benchmarks, whitelisted_caller};
use frame_system::RawOrigin;
use manta_token::*;
use sp_std::{boxed::Box, vec};
const SEED: u32 = 0;

benchmarks! {

	init {
		let caller: T::AccountId = whitelisted_caller();
	}: init (RawOrigin::Signed(caller.clone()), 1000)
	verify {
		assert_eq!(
			<TotalSupply>::get(), 1000
		)
	}


	transfer {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, 1000);
		assert!(Module::<T>::init(origin, 1000).is_ok());
		let recipient: T::AccountId = account("recipient", 0, SEED);
		let recipient_lookup: <T::Lookup as StaticLookup>::Source = T::Lookup::unlookup(recipient.clone());
		let transfer_amount = 10;
		Init::put(true);
	}: transfer(RawOrigin::Signed(caller.clone()), recipient_lookup, transfer_amount)
	verify {
		assert_eq!(Balances::<T>::get(&recipient), transfer_amount);
	}


	mint {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, 1000);
		assert!(Module::<T>::init(origin.clone(), 1000).is_ok());
		let amount = 10;

		// those are parameters for coin_1 in coin.json
		let mut k_bytes = [0u8; 32];
		let k_vec = BASE64
			.decode(b"+tMTpSikpdACxuDGZTl5pxwT7tpYcX/DFKJRZ1oLfqc=")
			.unwrap();
		k_bytes.copy_from_slice(k_vec[0..32].as_ref());

		let mut s_bytes = [0u8; 32];
		let s_vec = BASE64
			.decode(b"xsPXqMXA1SKMOehtsgVWV8xw9Mj0rh3O8Yt1ZHJzaQ4=")
			.unwrap();
		s_bytes.copy_from_slice(s_vec[0..32].as_ref());

		let mut cm_bytes = [0u8; 32];
		let cm_vec = BASE64
			.decode(b"XzoWOzhp6rXjQ/HDEN6jSLsLs64hKXWUNuFVtCUq0AA=")
			.unwrap();
		cm_bytes.copy_from_slice(cm_vec[0..32].as_ref());

		let mint_data = MintData {
			cm: cm_bytes,
			k: k_bytes,
			s: s_bytes,
		};

	}: mint (
		RawOrigin::Signed(caller),
		10,
		mint_data)
	verify {
		assert_eq!(TotalSupply::get(), 1000);
		assert_eq!(PoolBalance::get(), 10);
		let coin_list = CoinList::get();
		assert_eq!(coin_list.len(), 1);
		assert_eq!(coin_list[0], cm_bytes);
	}


	manta_transfer {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, 1000);
		assert!(Module::<T>::init(origin.clone(), 1000).is_ok());

		// hardcoded sender
		// those are parameters for coin_1 in coin.json
		let mut old_k_bytes = [0u8;32];
		let old_k_vec = BASE64
			.decode(b"+tMTpSikpdACxuDGZTl5pxwT7tpYcX/DFKJRZ1oLfqc=")
			.unwrap();
		old_k_bytes.copy_from_slice(&old_k_vec[0..32].as_ref());

		let mut old_s_bytes = [0u8; 32];
		let old_s_vec = BASE64
			.decode(b"xsPXqMXA1SKMOehtsgVWV8xw9Mj0rh3O8Yt1ZHJzaQ4=")
			.unwrap();
		old_s_bytes.copy_from_slice(old_s_vec[0..32].as_ref());

		let mut old_cm_bytes = [0u8; 32];
		let old_cm_vec = BASE64
			.decode(b"XzoWOzhp6rXjQ/HDEN6jSLsLs64hKXWUNuFVtCUq0AA=")
			.unwrap();
		old_cm_bytes.copy_from_slice(&old_cm_vec[0..32].as_ref());

		let mut old_sn_bytes = [0u8; 32];
		let old_sn_vec = BASE64
			.decode(b"jqhzAPanABquT0CpMC2aFt2ze8+UqMUcUG6PZBmqFqE=")
			.unwrap();
		old_sn_bytes.copy_from_slice(&old_sn_vec[0..32].as_ref());

		let mint_data = MintData {
			cm: old_cm_bytes,
			k: old_k_bytes,
			s: old_s_bytes,
		};

		// mint the sender coin
		assert!(Module::<T>::mint(
			origin,
			10,
			mint_data
		).is_ok());

		// check that minting is successful
		assert_eq!(PoolBalance::get(), 10);
		let coin_list = CoinList::get();
		assert_eq!(coin_list.len(), 1);
		assert_eq!(coin_list[0], old_cm_bytes);
		let sn_list = SNList::get();
		assert_eq!(sn_list.len(), 0);


		// hardcoded sender
		let sender_data = SenderData {
			k: old_k_bytes,
			sn: old_sn_bytes,
		};


		// hardcoded receiver
		// those are parameters for coin_2 in coin.json
		let mut new_k_bytes = [0u8;32];
		let new_k_vec = BASE64
			.decode(b"2HbWGQCLOfxuA4jOiDftBRSbjjAs/a0vjrq/H4p6QBI=")
			.unwrap();
		new_k_bytes.copy_from_slice(&new_k_vec[0..32].as_ref());

		let mut new_cm_bytes = [0u8; 32];
		let new_cm_vec = BASE64
			.decode(b"1zuOv92V7e1qX1bP7+QNsV+gW5E3xUsghte/lZ7h5pg=")
			.unwrap();
		new_cm_bytes.copy_from_slice(new_cm_vec[0..32].as_ref());

		// hardcoded keys and ciphertext
		let mut cipher_bytes = [0u8; 16];
		let cipher_vec =  BASE64
			.decode(b"UkNssYxe5HUjSzlz5JE1pQ==")
			.unwrap();
		cipher_bytes.copy_from_slice(cipher_vec[0..16].as_ref());

		let mut sender_pk_bytes = [0u8; 32];
		let sender_pk_vec =  BASE64
			.decode(b"YNwLbvb27Rb0aKptzSNEvBToYvW9IlbjVvROHfD2NAQ=")
			.unwrap();
		sender_pk_bytes.copy_from_slice(sender_pk_vec[0..32].as_ref());

		let mut receiver_sk_bytes = [0u8; 32];
		let receiver_sk_vec =  BASE64
			.decode(b"uPo5YiD6wGRiHbIXH6WmHuwjYS+mNSkCspDngkHHJ2c=")
			.unwrap();
		receiver_sk_bytes.copy_from_slice(receiver_sk_vec[0..32].as_ref());

		let receiver_data = ReceiverData {
			k: new_k_bytes,
			cm: new_cm_bytes,
			cipher: cipher_bytes,
		};

		// hardcoded proof
		let mut proof_bytes = [0u8; 192];
		let proof_vec = BASE64
			.decode(b"Z1m5tbfiMSrViXn5OAd3Ec5K+LpKQt9X/1G+dkiGugj25bFD0d63gJgAFs1Y9ZMMxX9N8a4OrrZCKzZ29iCGrwzoD7FCaIR5ggCd9ea3QkAgs7D1So+iVRPOFcUOEloW1vNSKNXE3pmjHlX3aj1YXJx255e2y3/639ANAuIbEGCrDPMQyj6gbYW9yqItZ3IDEHwU5mA2YSbFH0MweIRPp6aiOMY4GDjk3OEXNoA1YOxFXOTmIQRijyJin4+bxBEL")
			.unwrap();
		proof_bytes.copy_from_slice(proof_vec[0..192].as_ref());


		// hardcoded merkle root
		let mut root_bytes = [0u8; 32];
		let root_vec = BASE64
			.decode(b"7Can4hg4U8lJaMiuuDMoeB9vEo91bCtj+pvG17JXBRI=")
			.unwrap();
		root_bytes.copy_from_slice(root_vec[0..32].as_ref());

	}: manta_transfer (
		RawOrigin::Signed(caller),
		root_bytes,
		sender_data,
		receiver_data,
		proof_bytes)
	verify {
		assert_eq!(TotalSupply::get(), 1000);
		assert_eq!(PoolBalance::get(), 10);
		let coin_list = CoinList::get();
		assert_eq!(coin_list.len(), 2);
		assert_eq!(coin_list[0], old_cm_bytes);
		assert_eq!(coin_list[1], new_cm_bytes);
		let sn_list = SNList::get();
		assert_eq!(sn_list.len(), 1);
		assert_eq!(sn_list[0], old_sn_bytes);

		let enc_value_list = EncValueList::get();
		assert_eq!(enc_value_list.len(), 1);
		assert_eq!(enc_value_list[0], cipher_bytes);
		assert_eq!(
			dh::manta_dh_dec(&cipher_bytes, &sender_pk_bytes, &receiver_sk_bytes),
			10
		);
	}


	reclaim {
		let caller: T::AccountId = whitelisted_caller();
		let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
		<Balances<T>>::insert(&caller, 1000);
		assert!(Module::<T>::init(origin.clone(), 1000).is_ok());

		// hardcoded coin_1
		// those are parameters for coin_1 in coin.json
		let mut old_k_bytes = [0u8;32];
		let old_k_vec = BASE64
			.decode(b"+tMTpSikpdACxuDGZTl5pxwT7tpYcX/DFKJRZ1oLfqc=")
			.unwrap();
		old_k_bytes.copy_from_slice(&old_k_vec[0..32].as_ref());

		let mut old_s_bytes = [0u8; 32];
		let old_s_vec = BASE64
			.decode(b"xsPXqMXA1SKMOehtsgVWV8xw9Mj0rh3O8Yt1ZHJzaQ4=")
			.unwrap();
		old_s_bytes.copy_from_slice(old_s_vec[0..32].as_ref());

		let mut old_cm_bytes = [0u8; 32];
		let old_cm_vec = BASE64
			.decode(b"XzoWOzhp6rXjQ/HDEN6jSLsLs64hKXWUNuFVtCUq0AA=")
			.unwrap();
		old_cm_bytes.copy_from_slice(&old_cm_vec[0..32].as_ref());

		let mut old_sn_bytes = [0u8; 32];
		let old_sn_vec = BASE64
			.decode(b"jqhzAPanABquT0CpMC2aFt2ze8+UqMUcUG6PZBmqFqE=")
			.unwrap();
		old_sn_bytes.copy_from_slice(&old_sn_vec[0..32].as_ref());


		let mint_data = MintData {
			cm: old_cm_bytes,
			k: old_k_bytes,
			s: old_s_bytes,
		};

		// mint the sender coin
		assert!(Module::<T>::mint(
			origin.clone(),
			10,
			mint_data
		).is_ok());

		// check that minting is successful
		assert_eq!(PoolBalance::get(), 10);
		let coin_list = CoinList::get();
		assert_eq!(coin_list.len(), 1);
		assert_eq!(coin_list[0], old_cm_bytes);
		let sn_list = SNList::get();
		assert_eq!(sn_list.len(), 0);


		// hardcoded sender
		// those are parameters for coin_1 in coin.json
		let mut old_k_bytes = [0u8;32];
		let old_k_vec = BASE64
			.decode(b"2HbWGQCLOfxuA4jOiDftBRSbjjAs/a0vjrq/H4p6QBI=")
			.unwrap();
		old_k_bytes.copy_from_slice(&old_k_vec[0..32].as_ref());

		let mut old_s_bytes = [0u8; 32];
		let old_s_vec = BASE64
			.decode(b"LlXIi0kLQhSZ2SD0JaeckxgIiFuCaFbJh1IyI3675gw=")
			.unwrap();
		old_s_bytes.copy_from_slice(old_s_vec[0..32].as_ref());

		let mut old_cm_bytes = [0u8; 32];
		let old_cm_vec = BASE64
			.decode(b"1zuOv92V7e1qX1bP7+QNsV+gW5E3xUsghte/lZ7h5pg=")
			.unwrap();
		old_cm_bytes.copy_from_slice(&old_cm_vec[0..32].as_ref());

		let mut old_sn_bytes = [0u8; 32];
		let old_sn_vec = BASE64
			.decode(b"bwgOTJ8nNJ8phco73Zm6A8jV0ua6qsw9MtXtwyxV7cQ=")
			.unwrap();
		old_sn_bytes.copy_from_slice(&old_sn_vec[0..32].as_ref());

		let mint_data = MintData {
			cm: old_cm_bytes,
			k: old_k_bytes,
			s: old_s_bytes,
		};

		// mint the sender coin
		assert!(Module::<T>::mint(
			origin,
			10,
			mint_data
		).is_ok());


		// check that minting is successful
		assert_eq!(PoolBalance::get(), 20);
		let coin_list = CoinList::get();
		assert_eq!(coin_list.len(), 2);
		assert_eq!(coin_list[1], old_cm_bytes);
		let sn_list = SNList::get();
		assert_eq!(sn_list.len(), 0);


		// hardcoded sender
		let sender_data = SenderData {
			k: old_k_bytes,
			sn: old_sn_bytes,
		};

		// hardcoded proof
		let mut proof_bytes = [0u8; 192];
		let proof_vec = BASE64
			.decode(b"eZDMb5PzxupkaUtujU7oNKraGC5zN+OTYgPIvfSmIBjJWauLdJEhJoaM5FedPEyVvg2M9PTtJJR3OtBr1Wsc0iwpZwWzjD35exhT6sWisZshuZqtvjDItYNf12qiliQO6y+rf5rSSfkIA5awspGsAaqDelWNAAPblKdswzY7PXi0V/7FMmbi54M6QbW7PO0ZxW16HO4qN7cf2FGP9XNbcgsys8VS7pJXg5DQhHrYFW/xf0RlnIuSBeyiM3wIuMCO")
			.unwrap();
		proof_bytes.copy_from_slice(proof_vec[0..192].as_ref());

		// hardcoded merkle root
		let mut root_bytes = [0u8; 32];
		let root_vec = BASE64
			.decode(b"vRnz8gidII/pMapvEMSHUIIUsq3KP6Z4kqLf/Vshdz8=")
			.unwrap();
		root_bytes.copy_from_slice(root_vec[0..32].as_ref());
	}: reclaim (
		RawOrigin::Signed(caller),
		10,
		root_bytes,
		sender_data,
		proof_bytes)
	verify {
		// check the resulting status of the ledger storage
		assert_eq!(TotalSupply::get(), 1000);
		assert_eq!(PoolBalance::get(), 10);
		let coin_list = CoinList::get();
		assert_eq!(coin_list.len(), 2);
		let sn_list = SNList::get();
		assert_eq!(sn_list.len(), 1);
		assert_eq!(sn_list[0], old_sn_bytes);
	}
}
