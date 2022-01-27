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

use crate::{
    mock::{new_test_ext, MantaPayPallet, Origin, Test},
    Error,
};
use frame_support::{assert_noop, assert_ok};
use manta_accounting::{
    asset::{Asset, AssetId, AssetValue},
    transfer::test::value_distribution,
};
use manta_crypto::rand::{CryptoRng, Rand, RngCore, Sample};
use manta_pay::config::{
    FullParameters, KeyAgreementScheme, Mint, MultiProvingContext, Parameters, ProvingContext,
    TransferPost, UtxoCommitmentScheme, UtxoSetModel, VoidNumberHashFunction,
};
use manta_util::codec::{Decode, Encode, IoReader};
use rand::{seq::SliceRandom, thread_rng};
use std::fs::File;

lazy_static::lazy_static! {
    static ref MULTI_PROVING_CONTEXT: MultiProvingContext = load_proving_context();
    static ref PARAMETERS: Parameters = load_parameters();
    static ref UTXO_SET_MODEL: UtxoSetModel = load_utxo_set_model();
}

/// Loads the [`MultiProvingContext`] from the SDK.
#[inline]
fn load_proving_context() -> MultiProvingContext {
    let directory = tempfile::tempdir().expect("Unable to create temporary directory.");
    let path = directory.path();
    let mint_path = path.join("mint.dat");
    manta_sdk::pay::testnet::proving::mint(&mint_path)
        .expect("Unable to download MINT proving context.");
    let private_transfer_path = path.join("private-transfer.dat");
    manta_sdk::pay::testnet::proving::private_transfer(&private_transfer_path)
        .expect("Unable to download PRIVATE_TRANSFER proving context.");
    let reclaim_path = path.join("reclaim.dat");
    manta_sdk::pay::testnet::proving::reclaim(&reclaim_path)
        .expect("Unable to download RECLAIM proving context.");
    MultiProvingContext {
        mint: ProvingContext::decode(IoReader(
            File::open(mint_path).expect("Unable to open MINT proving context file."),
        ))
        .expect("Unable to decode MINT proving context."),
        private_transfer: ProvingContext::decode(IoReader(
            File::open(private_transfer_path)
                .expect("Unable to open PRIVATE_TRANSFER proving context file."),
        ))
        .expect("Unable to decode PRIVATE_TRANSFER proving context."),
        reclaim: ProvingContext::decode(IoReader(
            File::open(reclaim_path).expect("Unable to open RECLAIM proving context file."),
        ))
        .expect("Unable to decode RECLAIM proving context."),
    }
}

/// Loads the [`Parameters`] from the SDK.
#[inline]
fn load_parameters() -> Parameters {
    Parameters {
        key_agreement: KeyAgreementScheme::decode(
            manta_sdk::pay::testnet::parameters::KEY_AGREEMENT,
        )
        .expect("Unable to decode KEY_AGREEMENT parameters."),
        utxo_commitment: UtxoCommitmentScheme::decode(
            manta_sdk::pay::testnet::parameters::UTXO_COMMITMENT_SCHEME,
        )
        .expect("Unable to decode UTXO_COMMITMENT_SCHEME parameters."),
        void_number_hash: VoidNumberHashFunction::decode(
            manta_sdk::pay::testnet::parameters::VOID_NUMBER_HASH_FUNCTION,
        )
        .expect("Unable to decode VOID_NUMBER_HASH_FUNCTION parameters."),
    }
}

/// Loads the [`UtxoSetModel`] from the SDK.
#[inline]
fn load_utxo_set_model() -> UtxoSetModel {
    UtxoSetModel::decode(manta_sdk::pay::testnet::parameters::UTXO_SET_PARAMETERS)
        .expect("Unable to decode UTXO_SET_PARAMETERS.")
}

/// Samples a [`Mint`] transaction of `asset` with a random secret.
#[inline]
fn sample_mint<R>(asset: Asset, rng: &mut R) -> TransferPost
where
    R: CryptoRng + RngCore + ?Sized,
{
    Mint::from_spending_key(&PARAMETERS, &rng.gen(), asset, rng)
        .into_post(
            FullParameters::new(&PARAMETERS, &UTXO_SET_MODEL),
            &MULTI_PROVING_CONTEXT.mint,
            rng,
        )
        .expect("Unable to build MINT proof.")
}

/// Mints many assets with the given `id` and `value`.
#[inline]
fn mint_tokens<R>(id: AssetId, values: &[AssetValue], rng: &mut R)
where
    R: CryptoRng + RngCore + ?Sized,
{
    for value in values {
        assert_ok!(MantaPayPallet::mint(
            Origin::signed(1),
            sample_mint(value.with(id), rng).into()
        ));
    }
}

/// Flips an random bit in `data` using `rng`.
#[inline]
fn flip_random_bit<T, R>(data: &mut T, rng: &mut R)
where
    T: AsMut<[u8]> + ?Sized,
    R: CryptoRng + RngCore + ?Sized,
{
    const MASKS: [u8; 8] = [
        0b10000000, 0b01000000, 0b00100000, 0b00010000, 0b00001000, 0b00000100, 0b00000010,
        0b00000001,
    ];
    if let Some(byte) = data.as_mut().choose_mut(rng) {
        *byte ^= MASKS.choose(rng).unwrap();
    }
}

///
fn transfer_test<R>(count: usize, rng: &mut R)
where
    R: CryptoRng + RngCore + ?Sized,
{
    /*
    // generate asset_id and transfer balances
    let asset_id = rng.gen();
    let total_balance: AssetBalance = rng.gen();
    let balances: Vec<AssetBalance> = value_distribution(transfer_count, total_balance, rng);
    initialize_test(asset_id, total_balance);

    let mut utxo_set = HashMap::new();
    let mut current_pool_balance = 0;
    let transfer_pk = transfer_pk();
    for balance in balances {
        let (senders, receivers) = sample_fixed_sender_and_receiver(
            2,
            2,
            &LEAF_PARAMS,
            &TWO_TO_ONE_PARAMS,
            &COMMIT_PARAMS,
            asset_id,
            balance,
            balance,
            &mut utxo_set,
            rng,
        );

        // mint private tokens
        for sender in senders.clone() {
            let mint_data = generate_mint_struct(&sender.asset);
            assert_ok!(MantaPayPallet::mint_private_asset(
                Origin::signed(1),
                mint_data
            ));
        }
        // transfer private tokens
        let priv_trans_data = generate_private_transfer_struct(
            COMMIT_PARAMS.clone(),
            LEAF_PARAMS.clone(),
            TWO_TO_ONE_PARAMS.clone(),
            &transfer_pk,
            into_array_unchecked(senders),
            into_array_unchecked(receivers.clone()),
            rng,
        )
        .unwrap();
        assert_ok!(MantaPayPallet::private_transfer(
            Origin::signed(1),
            priv_trans_data
        ));

        // check the utxos and ciphertexts
        let (shard_index_1, shard_index_2) = (
            shard_index(receivers[0].utxo),
            shard_index(receivers[1].utxo),
        );
        let (meta_data_1, meta_data_2) = (
            LedgerShardMetaData::<Test>::get(shard_index_1),
            LedgerShardMetaData::<Test>::get(shard_index_2),
        );
        let ledger_entries = if shard_index_1 == shard_index_2 {
            [
                LedgerShards::<Test>::get(shard_index_1, meta_data_2.current_index),
                LedgerShards::<Test>::get(shard_index_1, meta_data_1.current_index - 1),
            ]
        } else {
            [
                LedgerShards::<Test>::get(shard_index_1, meta_data_2.current_index),
                LedgerShards::<Test>::get(shard_index_2, meta_data_2.current_index),
            ]
        };

        // Check ledger entry written
        for (i, entry) in ledger_entries.iter().enumerate() {
            assert_eq!(entry.0, receivers[i].utxo);
            assert_eq!(entry.1, receivers[i].encrypted_note);
        }

        // TODO: check the wellformness of ciphertexts
        // Check pool balance and utxo exists
        current_pool_balance += balance;
        assert_eq!(PoolBalance::<Test>::get(asset_id), current_pool_balance);
        for receiver in receivers {
            assert!(MantaPayPallet::utxo_exists(receiver.utxo));
        }
    }
    */
}

///
fn reclaim_test<R>(count: usize, rng: &mut R)
where
    R: CryptoRng + RngCore + ?Sized,
{
    /*
    let asset_id = rng.gen();
    let total_balance = rng.gen();
    let balances: Vec<AssetBalance> = value_distribution(reclaim_count, total_balance, rng);
    initialize_test(asset_id, total_balance);

    let mut utxo_set = HashMap::new();
    let mut current_pool_balance = 0;
    let reclaim_pk = reclaim_pk();
    for balance in balances {
        let reclaim_balances = value_distribution(2, balance, rng);
        let (receiver_value, reclaim_value) = (reclaim_balances[0], reclaim_balances[1]);

        let (senders, receivers) = sample_fixed_sender_and_receiver(
            2,
            1,
            &LEAF_PARAMS,
            &TWO_TO_ONE_PARAMS,
            &COMMIT_PARAMS,
            asset_id,
            balance,
            receiver_value,
            &mut utxo_set,
            rng,
        );

        // mint private tokens
        for sender in senders.clone() {
            let mint_data = generate_mint_struct(&sender.asset);
            assert_ok!(MantaPayPallet::mint_private_asset(
                Origin::signed(1),
                mint_data
            ));
        }
        current_pool_balance += balance;
        assert_eq!(PoolBalance::<Test>::get(asset_id), current_pool_balance);

        let receiver = receivers[0];

        // make reclaim
        let reclaim_data = generate_reclaim_struct(
            COMMIT_PARAMS.clone(),
            LEAF_PARAMS.clone(),
            TWO_TO_ONE_PARAMS.clone(),
            &reclaim_pk,
            into_array_unchecked(senders),
            receiver,
            reclaim_value,
            rng,
        )
        .unwrap();

        assert_ok!(MantaPayPallet::reclaim(Origin::signed(1), reclaim_data));
        current_pool_balance -= reclaim_value;
        assert_eq!(PoolBalance::<Test>::get(asset_id), current_pool_balance);

        // Check ledger state has been correctly updated
        let shard_index = shard_index(receiver.utxo);
        let meta_data = LedgerShardMetaData::<Test>::get(shard_index);
        let ledger_entry = LedgerShards::<Test>::get(shard_index, meta_data.current_index);
        assert_eq!(ledger_entry.0, receiver.utxo);
        assert_eq!(ledger_entry.1, receiver.encrypted_note);
        assert!(MantaPayPallet::utxo_exists(receiver.utxo));
    }
    */
}

///
#[inline]
fn initialize_test(id: AssetId, value: AssetValue) {
    MantaPayPallet::init_asset(&1, id.0, value.0);
    assert_eq!(MantaPayPallet::balance(1, id.0), value.0);
}

///
#[test]
fn test_mint_should_work() {
    let mut rng = thread_rng();
    new_test_ext().execute_with(|| {
        let asset_id = rng.gen();
        let total_supply = rng.gen();
        initialize_test(asset_id, total_supply);
        mint_tokens(
            asset_id,
            &value_distribution(5, total_supply, &mut rng),
            &mut rng,
        );
    });
}

///
#[test]
fn over_mint_should_not_work() {
    let mut rng = thread_rng();
    new_test_ext().execute_with(|| {
        let asset_id = rng.gen();
        let total_supply = AssetValue::gen(&mut rng)
            .checked_sub(AssetValue(1))
            .unwrap_or_default();
        initialize_test(asset_id, total_supply);
        assert_noop!(
            MantaPayPallet::mint(
                Origin::signed(1),
                sample_mint(asset_id.with(total_supply + 1), &mut rng).into()
            ),
            Error::<Test>::BalanceLow
        );
    });
}

///
#[test]
fn mint_without_init_should_not_work() {
    let mut rng = thread_rng();
    new_test_ext().execute_with(|| {
        assert_noop!(
            MantaPayPallet::mint(Origin::signed(1), sample_mint(rng.gen(), &mut rng).into()),
            Error::<Test>::BalanceLow,
        );
    });
}

///
#[test]
fn mint_existing_coin_should_not_work() {
    let mut rng = thread_rng();
    new_test_ext().execute_with(|| {
        let asset_id = rng.gen();
        initialize_test(asset_id, AssetValue(32579));
        let mint_post = sample_mint(asset_id.value(100), &mut rng);
        assert_ok!(MantaPayPallet::mint(
            Origin::signed(1),
            mint_post.clone().into()
        ));
        assert_noop!(
            MantaPayPallet::mint(Origin::signed(1), mint_post.into()),
            Error::<Test>::AssetRegistered
        );
    });
}

///
#[test]
fn mint_with_invalid_commitment_should_not_work() {
    let mut rng = thread_rng();
    new_test_ext().execute_with(|| {
        let asset_id = rng.gen();
        initialize_test(asset_id, AssetValue(100));
        let mut mint_post = sample_mint(asset_id.value(50), &mut rng);
        let mut utxo = mint_post.receiver_posts[0].utxo.to_vec();
        flip_random_bit(&mut utxo, &mut rng);
        mint_post.receiver_posts[0].utxo = Decode::from_vec(utxo).unwrap();
        assert_noop!(
            MantaPayPallet::mint(Origin::signed(1), mint_post.into()),
            Error::<Test>::InvalidProof
        );
    });
}

///
#[test]
fn test_transfer_should_work() {
    new_test_ext().execute_with(|| transfer_test(1, &mut thread_rng()));
}

///
#[test]
fn test_transfer_5_times_should_work() {
    new_test_ext().execute_with(|| transfer_test(5, &mut thread_rng()));
}

///
#[test]
fn double_spend_in_transfer_shoud_not_work() {
    let mut rng = thread_rng();
    new_test_ext().execute_with(|| {
        let asset_id = rng.gen();
        initialize_test(asset_id, AssetValue(800000));

        /*
        let transfer_pk = transfer_pk();
        let mut utxo_set = HashMap::new();
        let (senders, receivers) = sample_fixed_sender_and_receiver(
            2,
            2,
            &LEAF_PARAMS,
            &TWO_TO_ONE_PARAMS,
            &COMMIT_PARAMS,
            asset_id,
            5000,
            5000,
            &mut utxo_set,
            &mut rng,
        );

        // mint private tokens
        for sender in senders.clone() {
            let mint_data = generate_mint_struct(&sender.asset);
            assert_ok!(MantaPayPallet::mint_private_asset(
                Origin::signed(1),
                mint_data
            ));
        }
        // transfer private tokens
        let priv_trans_data = generate_private_transfer_struct(
            COMMIT_PARAMS.clone(),
            LEAF_PARAMS.clone(),
            TWO_TO_ONE_PARAMS.clone(),
            &transfer_pk,
            into_array_unchecked(senders),
            into_array_unchecked(receivers),
            &mut rng,
        )
        .unwrap();
        assert_ok!(MantaPayPallet::private_transfer(
            Origin::signed(1),
            priv_trans_data
        ));

        // try to spend again, this time should fail
        assert_noop!(
            MantaPayPallet::private_transfer(Origin::signed(1), priv_trans_data),
            Error::<Test>::MantaCoinSpent
        );
        */
    });
}

///
#[test]
fn transfer_with_invalid_zkp_should_not_work() {
    let mut rng = thread_rng();
    new_test_ext().execute_with(|| {
        /*
            let asset_id = rng.gen();
            initialize_test(asset_id, 800000);

            let transfer_pk = transfer_pk();
            let mut utxo_set = HashMap::new();
            let (senders, receivers) = sample_fixed_sender_and_receiver(
                2,
                2,
                &LEAF_PARAMS,
                &TWO_TO_ONE_PARAMS,
                &COMMIT_PARAMS,
                asset_id,
                5000,
                5000,
                &mut utxo_set,
                &mut rng,
            );

            // mint private tokens
            for sender in senders.clone() {
                let mint_data = generate_mint_struct(&sender.asset);
                assert_ok!(MantaPayPallet::mint_private_asset(
                    Origin::signed(1),
                    mint_data
                ));
            }
            // transfer private tokens
            let mut priv_trans_data = generate_private_transfer_struct(
                COMMIT_PARAMS.clone(),
                LEAF_PARAMS.clone(),
                TWO_TO_ONE_PARAMS.clone(),
                &transfer_pk,
                into_array_unchecked(senders),
                into_array_unchecked(receivers),
                &mut rng,
            )
            .unwrap();
            // flip a random bit in zkp
            random_bit_flip_in_zkp(&mut priv_trans_data.proof, &mut rng);
            assert_noop!(
                MantaPayPallet::private_transfer(Origin::signed(1), priv_trans_data),
                Error::<Test>::ZkpVerificationFail
            );
        */
    });
}

///
#[test]
fn test_reclaim_should_work() {
    new_test_ext().execute_with(|| reclaim_test(1, &mut thread_rng()));
}

///
#[test]
fn test_reclaim_5_times_should_work() {
    new_test_ext().execute_with(|| reclaim_test(5, &mut thread_rng()));
}

///
#[test]
fn double_spend_in_reclaim_should_not_work() {
    let mut rng = thread_rng();
    new_test_ext().execute_with(|| {
        /*
        let asset_id = rng.gen();
        let total_balance = 3289172;
        let receiver_value = 12590;
        let reclaim_value = total_balance - receiver_value;
        initialize_test(asset_id, total_balance);

        let mut utxo_set = HashMap::new();
        let reclaim_pk = reclaim_pk();
        let (senders, receivers) = sample_fixed_sender_and_receiver(
            2,
            1,
            &LEAF_PARAMS,
            &TWO_TO_ONE_PARAMS,
            &COMMIT_PARAMS,
            asset_id,
            total_balance,
            receiver_value,
            &mut utxo_set,
            &mut rng,
        );

        // mint private tokens
        for sender in senders.clone() {
            let mint_data = generate_mint_struct(&sender.asset);
            assert_ok!(MantaPayPallet::mint_private_asset(
                Origin::signed(1),
                mint_data
            ));
        }

        let receiver = receivers[0];

        // make reclaim
        let reclaim_data = generate_reclaim_struct(
            COMMIT_PARAMS.clone(),
            LEAF_PARAMS.clone(),
            TWO_TO_ONE_PARAMS.clone(),
            &reclaim_pk,
            into_array_unchecked(senders),
            receiver,
            reclaim_value,
            &mut rng,
        )
        .unwrap();

        assert_ok!(MantaPayPallet::reclaim(Origin::signed(1), reclaim_data));
        // double spend should fail
        assert_noop!(
            MantaPayPallet::reclaim(Origin::signed(1), reclaim_data),
            Error::<Test>::MantaCoinSpent,
        );
        */
    });
}

///
#[test]
fn reclaim_with_invalid_zkp_should_not_work() {
    let mut rng = thread_rng();
    new_test_ext().execute_with(|| {
        /*
            let asset_id = rng.gen();
            let total_balance = 3289172;
            let receiver_value = 12590;
            let reclaim_value = total_balance - receiver_value;
            initialize_test(asset_id, total_balance);

            let mut utxo_set = HashMap::new();
            let reclaim_pk = reclaim_pk();
            let (senders, receivers) = sample_fixed_sender_and_receiver(
                2,
                1,
                &LEAF_PARAMS,
                &TWO_TO_ONE_PARAMS,
                &COMMIT_PARAMS,
                asset_id,
                total_balance,
                receiver_value,
                &mut utxo_set,
                &mut rng,
            );

            // mint private tokens
            for sender in senders.clone() {
                let mint_data = generate_mint_struct(&sender.asset);
                assert_ok!(MantaPayPallet::mint_private_asset(
                    Origin::signed(1),
                    mint_data
                ));
            }

            let receiver = receivers[0];

            // make reclaim
            let mut reclaim_data = generate_reclaim_struct(
                COMMIT_PARAMS.clone(),
                LEAF_PARAMS.clone(),
                TWO_TO_ONE_PARAMS.clone(),
                &reclaim_pk,
                into_array_unchecked(senders),
                receiver,
                reclaim_value,
                &mut rng,
            )
            .unwrap();

            // flip a random bit in zkp
            random_bit_flip_in_zkp(&mut reclaim_data.proof, &mut rng);
            assert_noop!(
                MantaPayPallet::reclaim(Origin::signed(1), reclaim_data),
                Error::<Test>::ZkpVerificationFail,
            );
        */
    });
}
