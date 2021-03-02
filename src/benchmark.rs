//! manta-dap pallet benchmarking.

#![cfg(feature = "runtime-benchmarks")]

use super::*;
use data_encoding::BASE64;
use frame_benchmarking::{account, benchmarks, whitelisted_caller};
use frame_system::RawOrigin;
use sp_std::boxed::Box;
use sp_std::vec;

benchmarks! {
    _ { }

    init {
        let caller: T::AccountId = whitelisted_caller();
    }: init(RawOrigin::Signed(caller.clone()), 1000)
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

        let coin = MantaCoin {
            cm_bytes: cm_bytes.clone(),
        };

    }: mint(
        RawOrigin::Signed(caller),
        10,
        k_bytes,
        s_bytes,
        cm_bytes)
    verify {
        assert_eq!(TotalSupply::get(), 1000);
        assert_eq!(PoolBalance::get(), 10);
        let coin_list = CoinList::get();
        assert_eq!(coin_list.len(), 1);
        assert_eq!(coin_list[0], coin);
    }


    manta_transfer {
        let caller: T::AccountId = whitelisted_caller();
        let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
        <Balances<T>>::insert(&caller, 1000);
        assert!(Module::<T>::init(origin.clone(), 1000).is_ok());

        // hardcoded sender
        // those are parameters for coin_1 in coin.json
        let  mut old_k_bytes = [0u8;32];
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

        let sender = MantaCoin {
            cm_bytes: old_cm_bytes.clone(),
        };

        // mint the sender coin
        assert!(Module::<T>::mint(
            origin,
            10,
            old_k_bytes,
            old_s_bytes,
            old_cm_bytes
        ).is_ok());

        // check that minting is successful
        assert_eq!(PoolBalance::get(), 10);
        let coin_list = CoinList::get();
        assert_eq!(coin_list.len(), 1);
        assert_eq!(coin_list[0], sender);
        let sn_list = SNList::get();
        assert_eq!(sn_list.len(), 0);

        // hardcoded receiver
        // those are parameters for coin_3 in coin.json
        let  mut new_k_bytes = [0u8;32];
        let new_k_vec = BASE64
            .decode(b"2HbWGQCLOfxuA4jOiDftBRSbjjAs/a0vjrq/H4p6QBI=")
            .unwrap();
        new_k_bytes.copy_from_slice(&new_k_vec[0..32].as_ref());

        let mut new_cm_bytes = [0u8; 32];
        let new_cm_vec = BASE64
            .decode(b"1zuOv92V7e1qX1bP7+QNsV+gW5E3xUsghte/lZ7h5pg=")
            .unwrap();
        new_cm_bytes.copy_from_slice(new_cm_vec[0..32].as_ref());
        let receiver = MantaCoin{
            cm_bytes: new_cm_bytes,
        };

        // hardcoded proof
        let mut proof_bytes = [0u8; 192];
        let proof_vec = BASE64
            .decode(b"zU+xNmmLjmJAFy/sbxGR5fwik4nSddSjrn0YdygYlLSTvXHk8jVsjS4Sp4/0cuCHl+h9i9Scj5ok8q8R55QL2xuBZS7L0++N8BVL1HqzO0yFhrKiuScIg0cKWZYg76oBSK0xAbsMvmEoh+DQCsWG5Hfcey8BSXiaEck1LJFzpvRSqqsKChLC8cDN3fLH8fMJHh5tnAXDmMoOrKH2r7v7c0IJh0JjlWgazCEt9xb/89467vUfNAJ8jzIRl9zqsuqH")
            .unwrap();
        proof_bytes.copy_from_slice(proof_vec[0..192].as_ref());

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


        // hardcoded merkle root
        let mut root_bytes = [0u8; 32];
        let root_vec = BASE64
            .decode(b"q5VhDl/WxjeemZ/2ivGmiuOTFMEazcqEFk5ESISngso=")
            .unwrap();
        root_bytes.copy_from_slice(root_vec[0..32].as_ref());

    }: manta_transfer(
        RawOrigin::Signed(caller),
        root_bytes,
        old_sn_bytes,
        old_k_bytes,
        new_k_bytes,
        new_cm_bytes,
        cipher_bytes,
        proof_bytes)
    verify {
        assert_eq!(TotalSupply::get(), 1000);
        assert_eq!(PoolBalance::get(), 10);
        let coin_list = CoinList::get();
        assert_eq!(coin_list.len(), 2);
        assert_eq!(coin_list[0], sender);
        assert_eq!(coin_list[1], receiver);
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


    forfeit {
        let caller: T::AccountId = whitelisted_caller();
        let origin: T::Origin = T::Origin::from(RawOrigin::Signed(caller.clone()));
        <Balances<T>>::insert(&caller, 1000);
        assert!(Module::<T>::init(origin.clone(), 1000).is_ok());

        // hardcoded coin_1
        // those are parameters for coin_1 in coin.json
        let  mut old_k_bytes = [0u8;32];
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

        let sender = MantaCoin {
            cm_bytes: old_cm_bytes.clone(),
        };

        // mint the sender coin
        assert!(Module::<T>::mint(
            origin.clone(),
            10,
            old_k_bytes,
            old_s_bytes,
            old_cm_bytes
        ).is_ok());

        // check that minting is successful
        assert_eq!(PoolBalance::get(), 10);
        let coin_list = CoinList::get();
        assert_eq!(coin_list.len(), 1);
        assert_eq!(coin_list[0], sender);
        let sn_list = SNList::get();
        assert_eq!(sn_list.len(), 0);


        // hardcoded sender
        // those are parameters for coin_1 in coin.json
        let  mut old_k_bytes = [0u8;32];
        let old_k_vec = BASE64
            .decode(b"CutG9BBbkJMpBkbYTVX37HWunGcxHyy8+Eb1xRT9eVM=")
            .unwrap();
        old_k_bytes.copy_from_slice(&old_k_vec[0..32].as_ref());

        let mut old_s_bytes = [0u8; 32];
        let old_s_vec = BASE64
            .decode(b"/KTVGbHHU8UVHLS6h54470DtjwF6MHvBkG2bKxpyBQc=")
            .unwrap();
        old_s_bytes.copy_from_slice(old_s_vec[0..32].as_ref());

        let mut old_cm_bytes = [0u8; 32];
        let old_cm_vec = BASE64
            .decode(b"3Oye4AqhzdysdWdCzMcoImTnYNGd21OmF8ztph4dRqI=")
            .unwrap();
        old_cm_bytes.copy_from_slice(&old_cm_vec[0..32].as_ref());

        let mut old_sn_bytes = [0u8; 32];
        let old_sn_vec = BASE64
            .decode(b"EdHWc+HAgRWlcJrK8dlVnewSCTwEDPZFa8iYKxoRdOY=")
            .unwrap();
        old_sn_bytes.copy_from_slice(&old_sn_vec[0..32].as_ref());

        let sender = MantaCoin {
            cm_bytes: old_cm_bytes.clone(),
        };

        // mint the sender coin
        assert!(Module::<T>::mint(
            origin,
            100,
            old_k_bytes,
            old_s_bytes,
            old_cm_bytes
        ).is_ok());

        // check that minting is successful
        assert_eq!(PoolBalance::get(), 110);
        let coin_list = CoinList::get();
        assert_eq!(coin_list.len(), 2);
        assert_eq!(coin_list[1], sender);
        let sn_list = SNList::get();
        assert_eq!(sn_list.len(), 0);


        // hardcoded proof
        let mut proof_bytes = [0u8; 192];
        let proof_vec = BASE64
            .decode(b"yT4284c8SiAC1i85GIgmOJa20KjLGWGTrdsvLOo6bbPgtPO8qDpK8y6OtiOa1qqSxm+tp1CAjxdyrTQ6QkZqUQfJs51cvrp9vYYscY2LqqRcuYL1T7LRq/IcofgJZf8YyRH3HWnz5Vj/bXmFAVlLgs/fbWYgzoFHbOlZpva+RMgCMuJ/2ltRAfpKDI7meMgBwEMSz93OPGv+txf0yhVqydpSVrFdB/zwd09mWW/7OuCYRzXcvmBuL3HGzbsGiLkG")
            .unwrap();
        proof_bytes.copy_from_slice(proof_vec[0..192].as_ref());

        // hardcoded merkle root
        let mut root_bytes = [0u8; 32];
        let root_vec = BASE64
            .decode(b"QDWIJvSmMmIS1incXpqZA+oZKOuvP42PNVyLKWC0gGQ=")
            .unwrap();
        root_bytes.copy_from_slice(root_vec[0..32].as_ref());
    }: forfeit(
        RawOrigin::Signed(caller),
        100,
        root_bytes,
        old_sn_bytes,
        old_k_bytes,
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
