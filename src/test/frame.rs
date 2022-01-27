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
    transfer::{self, test::value_distribution, SpendingKey},
};
use manta_crypto::{
    accumulator::Accumulator,
    merkle_tree::{forest::TreeArrayMerkleForest, full::Full},
    rand::{CryptoRng, Rand, RngCore, Sample},
};
use manta_pay::config::{
    FullParameters, KeyAgreementScheme, MerkleTreeConfiguration, Mint, MultiProvingContext,
    Parameters, PrivateTransfer, ProvingContext, Reclaim, TransferPost, UtxoCommitmentScheme,
    UtxoSetModel, VoidNumberHashFunction,
};
use manta_util::codec::{Decode, IoReader};
use rand::thread_rng;
use std::fs::File;

/// UTXO Set for Building Circuits
type UtxoSet = TreeArrayMerkleForest<MerkleTreeConfiguration, Full<MerkleTreeConfiguration>, 256>;

lazy_static::lazy_static! {
    static ref PROVING_CONTEXT: MultiProvingContext = load_proving_context();
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
            &PROVING_CONTEXT.mint,
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

/// Builds `count`-many [`PrivateTransfer`] tests.
#[inline]
fn private_transfer_test<R>(count: usize, rng: &mut R) -> Vec<TransferPost>
where
    R: CryptoRng + RngCore + ?Sized,
{
    let asset_id = rng.gen();
    let total_balance = rng.gen();
    let balances = value_distribution(count, total_balance, rng);
    initialize_test(asset_id, total_balance);
    let mut utxo_set = UtxoSet::new(UTXO_SET_MODEL.clone());
    let mut posts = Vec::new();
    for balance in balances {
        let spending_key = SpendingKey::gen(rng);
        let (mint_0, pre_sender_0) = transfer::test::sample_mint(
            &PROVING_CONTEXT.mint,
            FullParameters::new(&PARAMETERS, utxo_set.model()),
            &spending_key,
            asset_id.with(balance),
            rng,
        )
        .unwrap();
        assert_ok!(MantaPayPallet::mint(Origin::signed(1), mint_0.into()));
        let sender_0 = pre_sender_0
            .insert_and_upgrade(&mut utxo_set)
            .expect("Just inserted so this should not fail.");
        let (mint_1, pre_sender_1) = transfer::test::sample_mint(
            &PROVING_CONTEXT.mint,
            FullParameters::new(&PARAMETERS, utxo_set.model()),
            &spending_key,
            asset_id.value(0),
            rng,
        )
        .unwrap();
        assert_ok!(MantaPayPallet::mint(Origin::signed(1), mint_1.into()));
        let sender_1 = pre_sender_1
            .insert_and_upgrade(&mut utxo_set)
            .expect("Just inserted so this should not fail.");
        let (receiver_0, pre_sender_0) =
            spending_key.internal_pair(&PARAMETERS, rng.gen(), asset_id.value(0));
        let (receiver_1, pre_sender_1) =
            spending_key.internal_pair(&PARAMETERS, rng.gen(), asset_id.with(balance));
        let private_transfer =
            PrivateTransfer::build([sender_0, sender_1], [receiver_0, receiver_1])
                .into_post(
                    FullParameters::new(&PARAMETERS, utxo_set.model()),
                    &PROVING_CONTEXT.private_transfer,
                    rng,
                )
                .unwrap();
        assert_ok!(MantaPayPallet::private_transfer(
            Origin::signed(1),
            private_transfer.clone().into(),
        ));
        pre_sender_0.insert_utxo(&mut utxo_set);
        pre_sender_1.insert_utxo(&mut utxo_set);
        posts.push(private_transfer)
    }
    posts
}

/// Builds `count`-many [`Reclaim`] tests.
#[inline]
fn reclaim_test<R>(count: usize, rng: &mut R) -> Vec<TransferPost>
where
    R: CryptoRng + RngCore + ?Sized,
{
    let asset_id = rng.gen();
    let total_balance = rng.gen();
    let balances = value_distribution(count, total_balance, rng);
    initialize_test(asset_id, total_balance);
    let mut utxo_set = UtxoSet::new(UTXO_SET_MODEL.clone());
    let mut posts = Vec::new();
    for balance in balances {
        let spending_key = SpendingKey::gen(rng);
        let (mint_0, pre_sender_0) = transfer::test::sample_mint(
            &PROVING_CONTEXT.mint,
            FullParameters::new(&PARAMETERS, utxo_set.model()),
            &spending_key,
            asset_id.with(balance),
            rng,
        )
        .unwrap();
        assert_ok!(MantaPayPallet::mint(Origin::signed(1), mint_0.into()));
        let sender_0 = pre_sender_0
            .insert_and_upgrade(&mut utxo_set)
            .expect("Just inserted so this should not fail.");
        let (mint_1, pre_sender_1) = transfer::test::sample_mint(
            &PROVING_CONTEXT.mint,
            FullParameters::new(&PARAMETERS, utxo_set.model()),
            &spending_key,
            asset_id.value(0),
            rng,
        )
        .unwrap();
        assert_ok!(MantaPayPallet::mint(Origin::signed(1), mint_1.into()));
        let sender_1 = pre_sender_1
            .insert_and_upgrade(&mut utxo_set)
            .expect("Just inserted so this should not fail.");
        let (receiver, pre_sender) =
            spending_key.internal_pair(&PARAMETERS, rng.gen(), asset_id.value(0));
        let reclaim = Reclaim::build([sender_0, sender_1], [receiver], asset_id.with(balance))
            .into_post(
                FullParameters::new(&PARAMETERS, utxo_set.model()),
                &PROVING_CONTEXT.reclaim,
                rng,
            )
            .unwrap();
        assert_ok!(MantaPayPallet::reclaim(
            Origin::signed(1),
            reclaim.clone().into()
        ));
        pre_sender.insert_utxo(&mut utxo_set);
        posts.push(reclaim);
    }
    posts
}

/// Initializes a test by allocating `value`-many assets of the given `id` to the default account.
#[inline]
fn initialize_test(id: AssetId, value: AssetValue) {
    MantaPayPallet::init_asset(&1, id.0, value.0);
    assert_eq!(MantaPayPallet::balance(1, id.0), value.0);
}

/// Tests multiple mints from some total supply.
#[test]
fn mint_should_work() {
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

/// Tests a mint that would overdraw the total supply.
#[test]
fn overdrawn_mint_should_not_work() {
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

/// Tests a mint that would overdraw from a non-existent supply.
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

/// Tests that a double-spent [`Mint`] will fail.
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

/// Tests a [`PrivateTransfer`] transaction.
#[test]
fn private_transfer_should_work() {
    new_test_ext().execute_with(|| private_transfer_test(1, &mut thread_rng()));
}

/// Tests multiple [`PrivateTransfer`] transactions.
#[test]
fn private_transfer_10_times_should_work() {
    new_test_ext().execute_with(|| private_transfer_test(10, &mut thread_rng()));
}

/// Tests that a double-spent [`PrivateTransfer`] will fail.
#[test]
fn double_spend_in_private_transfer_should_not_work() {
    new_test_ext().execute_with(|| {
        for private_transfer in private_transfer_test(1, &mut thread_rng()) {
            assert_noop!(
                MantaPayPallet::private_transfer(Origin::signed(1), private_transfer.into()),
                Error::<Test>::AssetSpent,
            );
        }
    });
}

/// Tests a [`Reclaim`] transaction.
#[test]
fn reclaim_should_work() {
    new_test_ext().execute_with(|| reclaim_test(1, &mut thread_rng()));
}

/// Tests multiple [`Reclaim`] transactions.
#[test]
fn reclaim_10_times_should_work() {
    new_test_ext().execute_with(|| reclaim_test(10, &mut thread_rng()));
}

/// Tests that a double-spent [`Reclaim`] will fail.
#[test]
fn double_spend_in_reclaim_should_not_work() {
    new_test_ext().execute_with(|| {
        for reclaim in reclaim_test(1, &mut thread_rng()) {
            assert_noop!(
                MantaPayPallet::reclaim(Origin::signed(1), reclaim.into()),
                Error::<Test>::AssetSpent,
            );
        }
    });
}
