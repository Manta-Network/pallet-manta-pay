use crate as pallet_manta_dap;
use crate::*;
use data_encoding::BASE64;
use frame_support::{assert_ok, parameter_types};
use sp_core::H256;
use sp_runtime::{
	testing::Header,
	traits::{BlakeTwo256, IdentityLookup},
};

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
	pub enum Test where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = UncheckedExtrinsic,
	{
		System: frame_system::{Module, Call, Config, Storage, Event<T>},
		MantaModule: pallet_manta_dap::{Module, Call, Storage, Event<T>},
	}
);
type BlockNumber = u64;

parameter_types! {
	pub const BlockHashCount: BlockNumber = 250;
	pub const SS58Prefix: u8 = 42;
}

impl frame_system::Config for Test {
	type BaseCallFilter = ();
	type Origin = Origin;
	type Index = u64;
	type Call = Call;
	type BlockNumber = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = u64;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Header = Header;
	type Event = ();
	type BlockHashCount = BlockHashCount;
	type DbWeight = ();
	type Version = ();
	type AccountData = ();
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type PalletInfo = PalletInfo;
	type BlockWeights = ();
	type BlockLength = ();
	type SS58Prefix = SS58Prefix;
}

impl Config for Test {
	type Event = ();
}
type Assets = Module<Test>;

fn new_test_ext() -> sp_io::TestExternalities {
	frame_system::GenesisConfig::default()
		.build_storage::<Test>()
		.unwrap()
		.into()
}

#[test]
fn test_mint_hardcode_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Assets::init(Origin::signed(1), 1000));
		assert_eq!(Assets::balance(1), 1000);
		assert_eq!(PoolBalance::get(), 0);

		// those are parameters for coin_1 in coin.json
		let k_vec = BASE64
			.decode(b"+tMTpSikpdACxuDGZTl5pxwT7tpYcX/DFKJRZ1oLfqc=")
			.unwrap();

		let s_vec = BASE64
			.decode(b"xsPXqMXA1SKMOehtsgVWV8xw9Mj0rh3O8Yt1ZHJzaQ4=")
			.unwrap();

		let cm_vec = BASE64
			.decode(b"XzoWOzhp6rXjQ/HDEN6jSLsLs64hKXWUNuFVtCUq0AA=")
			.unwrap();

		let mut mint_data = [0u8; 96];
		mint_data.copy_from_slice([cm_vec.clone(), k_vec, s_vec].concat().as_ref());

		assert_ok!(Assets::mint(Origin::signed(1), 10, mint_data));

		assert_eq!(TotalSupply::get(), 1000);
		assert_eq!(PoolBalance::get(), 10);
		let coin_shards = CoinShards::get();
		let mut cm_bytes = [0u8; 32];
		cm_bytes.copy_from_slice(cm_vec.as_ref());
		assert!(coin_shards.exist(&cm_bytes));

		// those are parameters for coin_2 in coin.json
		let k_vec = BASE64
			.decode(b"CutG9BBbkJMpBkbYTVX37HWunGcxHyy8+Eb1xRT9eVM=")
			.unwrap();

		let s_vec = BASE64
			.decode(b"/KTVGbHHU8UVHLS6h54470DtjwF6MHvBkG2bKxpyBQc=")
			.unwrap();

		let cm_vec = BASE64
			.decode(b"3Oye4AqhzdysdWdCzMcoImTnYNGd21OmF8ztph4dRqI=")
			.unwrap();

		let mut mint_data = [0u8; 96];
		mint_data.copy_from_slice([cm_vec.clone(), k_vec, s_vec].concat().as_ref());

		assert_ok!(Assets::mint(Origin::signed(1), 100, mint_data));

		assert_eq!(TotalSupply::get(), 1000);
		assert_eq!(PoolBalance::get(), 110);
		let coin_shards = CoinShards::get();
		let mut cm_bytes = [0u8; 32];
		cm_bytes.copy_from_slice(cm_vec.as_ref());
		assert!(coin_shards.exist(&cm_bytes));

		let sn_list = SNList::get();
		assert_eq!(sn_list.len(), 0);
	});
}

#[test]
fn test_transfer_hardcode_should_work() {
	new_test_ext().execute_with(|| {
        assert_ok!(Assets::init(Origin::signed(1), 1000));
        assert_eq!(Assets::balance(1), 1000);
        assert_eq!(PoolBalance::get(), 0);

        // hardcoded sender
        // those are parameters for coin_1 in coin.json
        let old_k_vec = BASE64
            .decode(b"+tMTpSikpdACxuDGZTl5pxwT7tpYcX/DFKJRZ1oLfqc=")
            .unwrap();

        let old_s_vec = BASE64
            .decode(b"xsPXqMXA1SKMOehtsgVWV8xw9Mj0rh3O8Yt1ZHJzaQ4=")
            .unwrap();

        let old_cm_vec = BASE64
            .decode(b"XzoWOzhp6rXjQ/HDEN6jSLsLs64hKXWUNuFVtCUq0AA=")
            .unwrap();

        let old_sn_vec = BASE64
            .decode(b"jqhzAPanABquT0CpMC2aFt2ze8+UqMUcUG6PZBmqFqE=")
            .unwrap();

        let mut mint_data = [0u8; 96];
        mint_data.copy_from_slice([
            old_cm_vec.clone(),
            old_k_vec.clone(),
            old_s_vec
        ].concat().as_ref());

        // mint the sender coin
        assert_ok!(Assets::mint(
            Origin::signed(1),
            10,
            mint_data
        ));

        // check that minting is successful
        assert_eq!(PoolBalance::get(), 10);
		let coin_shards = CoinShards::get();
        let mut cm_bytes = [0u8; 32];
        cm_bytes.copy_from_slice(old_cm_vec.as_ref());
        assert!(coin_shards.exist(&cm_bytes));
        let sn_list = SNList::get();
        assert_eq!(sn_list.len(), 0);

        // hardcoded receiver
        // those are parameters for coin_2 in coin.json
        let new_k_vec = BASE64
            .decode(b"2HbWGQCLOfxuA4jOiDftBRSbjjAs/a0vjrq/H4p6QBI=")
            .unwrap();

        let new_cm_vec = BASE64
            .decode(b"1zuOv92V7e1qX1bP7+QNsV+gW5E3xUsghte/lZ7h5pg=")
            .unwrap();

        // hardcoded proof
        let mut proof_bytes = [0u8; 192];
        let proof_vec = BASE64
            .decode(b"Z1m5tbfiMSrViXn5OAd3Ec5K+LpKQt9X/1G+dkiGugj25bFD0d63gJgAFs1Y9ZMMxX9N8a4OrrZCKzZ29iCGrwzoD7FCaIR5ggCd9ea3QkAgs7D1So+iVRPOFcUOEloW1vNSKNXE3pmjHlX3aj1YXJx255e2y3/639ANAuIbEGCrDPMQyj6gbYW9yqItZ3IDEHwU5mA2YSbFH0MweIRPp6aiOMY4GDjk3OEXNoA1YOxFXOTmIQRijyJin4+bxBEL")
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
            .decode(b"7Can4hg4U8lJaMiuuDMoeB9vEo91bCtj+pvG17JXBRI=")
            .unwrap();
        root_bytes.copy_from_slice(root_vec[0..32].as_ref());

        let mut sender_data = [0u8; 64];
        sender_data.copy_from_slice([old_k_vec, old_sn_vec.clone()].concat().as_ref());

        let mut receiver_data = [0u8; 80];
        receiver_data.copy_from_slice([
            new_k_vec,
            new_cm_vec.clone(),
            cipher_vec
        ].concat().as_ref());

        // make the transfer
        assert_ok!(Assets::manta_transfer(
            Origin::signed(1),
            root_bytes,
            sender_data,
            receiver_data,
            proof_bytes,
        ));

        // check the resulting status of the ledger storage
        assert_eq!(TotalSupply::get(), 1000);
        assert_eq!(PoolBalance::get(), 10);
		let coin_shards = CoinShards::get();
        let mut cm_bytes = [0u8; 32];
        cm_bytes.copy_from_slice(old_cm_vec.as_ref());
        assert!(coin_shards.exist(&cm_bytes));
        cm_bytes.copy_from_slice(new_cm_vec.as_ref());
        assert!(coin_shards.exist(&cm_bytes));
        let sn_list = SNList::get();
        assert_eq!(sn_list.len(), 1);
        assert_eq!(sn_list[0].as_ref(), old_sn_vec);

        let enc_value_list = EncValueList::get();
        assert_eq!(enc_value_list.len(), 1);
        assert_eq!(enc_value_list[0], cipher_bytes);
        assert_eq!(
            dh::manta_dh_dec(&cipher_bytes, &sender_pk_bytes, &receiver_sk_bytes),
            10
        );

        // todo: check the ledger state is correctly updated
    });
}


// TODO fix this test
// #[test]
// fn test_reclaim_hardcode_should_work() {
// 	new_test_ext().execute_with(|| {
//         assert_ok!(Assets::init(Origin::signed(1), 1000));
//         assert_eq!(Assets::balance(1), 1000);
//         assert_eq!(PoolBalance::get(), 0);

//         // hardcoded coin_1
//         // those are parameters for coin_1 in coin.json
//         let old_k_vec = BASE64
//             .decode(b"+tMTpSikpdACxuDGZTl5pxwT7tpYcX/DFKJRZ1oLfqc=")
//             .unwrap();

//         let old_s_vec = BASE64
//             .decode(b"xsPXqMXA1SKMOehtsgVWV8xw9Mj0rh3O8Yt1ZHJzaQ4=")
//             .unwrap();

//         let old_cm_vec = BASE64
//             .decode(b"XzoWOzhp6rXjQ/HDEN6jSLsLs64hKXWUNuFVtCUq0AA=")
//             .unwrap();

//         // mint the first coin
//         let mut mint_data = [0u8; 96];
//         mint_data.copy_from_slice([
//             old_cm_vec.clone(),
//             old_k_vec,
//             old_s_vec
//         ].concat().as_ref());

//         assert_ok!(Assets::mint(
//             Origin::signed(1),
//             10,
//             mint_data
//         ));

//         // check that minting is successful
//         assert_eq!(PoolBalance::get(), 10);
// 		let coin_shards = CoinShards::get();
//         let mut cm_bytes = [0u8; 32];
//         cm_bytes.copy_from_slice(old_cm_vec.as_ref());
//         assert!(coin_shards.exist(&cm_bytes));
//         let sn_list = SNList::get();
//         assert_eq!(sn_list.len(), 0);

//         // hardcoded coin_2
//         // those are parameters for coin_2 in coin.json
//         let old_k_vec = BASE64
//             .decode(b"2HbWGQCLOfxuA4jOiDftBRSbjjAs/a0vjrq/H4p6QBI=")
//             .unwrap();

//         let old_s_vec = BASE64
//             .decode(b"LlXIi0kLQhSZ2SD0JaeckxgIiFuCaFbJh1IyI3675gw=")
//             .unwrap();

//         let old_cm_vec = BASE64
//             .decode(b"1zuOv92V7e1qX1bP7+QNsV+gW5E3xUsghte/lZ7h5pg=")
//             .unwrap();

//         let old_sn_vec = BASE64
//             .decode(b"bwgOTJ8nNJ8phco73Zm6A8jV0ua6qsw9MtXtwyxV7cQ=")
//             .unwrap();

//         // mint the second coin
//         let mut mint_data = [0u8; 96];
//         mint_data.copy_from_slice([
//             old_cm_vec.clone(),
//             old_k_vec.clone(),
//             old_s_vec
//         ].concat().as_ref());

//         assert_ok!(Assets::mint(
//             Origin::signed(1),
//             10,
//             mint_data
//         ));

//         // check that minting is successful
//         assert_eq!(PoolBalance::get(), 20);
// 		let coin_shards = CoinShards::get();
//         let mut cm_bytes = [0u8; 32];
//         cm_bytes.copy_from_slice(old_cm_vec.as_ref());
//         assert!(coin_shards.exist(&cm_bytes));
//         let sn_list = SNList::get();
//         assert_eq!(sn_list.len(), 0);

//         // hardcoded proof
//         let mut proof_bytes = [0u8; 192];
//         let proof_vec = BASE64
//             .decode(b"eZDMb5PzxupkaUtujU7oNKraGC5zN+OTYgPIvfSmIBjJWauLdJEhJoaM5FedPEyVvg2M9PTtJJR3OtBr1Wsc0iwpZwWzjD35exhT6sWisZshuZqtvjDItYNf12qiliQO6y+rf5rSSfkIA5awspGsAaqDelWNAAPblKdswzY7PXi0V/7FMmbi54M6QbW7PO0ZxW16HO4qN7cf2FGP9XNbcgsys8VS7pJXg5DQhHrYFW/xf0RlnIuSBeyiM3wIuMCO")
//             .unwrap();
//         proof_bytes.copy_from_slice(proof_vec[0..192].as_ref());

//         // hardcoded merkle root
//         let mut root_bytes = [0u8; 32];
//         let root_vec = BASE64
//             .decode(b"vRnz8gidII/pMapvEMSHUIIUsq3KP6Z4kqLf/Vshdz8=")
//             .unwrap();
//         root_bytes.copy_from_slice(root_vec[0..32].as_ref());

//         // make the transfer
//         let mut sender_data = [0u8; 64];
//         sender_data.copy_from_slice([
//             old_k_vec,
//             old_sn_vec.clone()
//         ].concat().as_ref());

//         assert_ok!(Assets::reclaim(
//             Origin::signed(1),
//             10,
//             root_bytes,
//             sender_data,
//             proof_bytes,
//         ));

//         // check the resulting status of the ledger storage
//         assert_eq!(TotalSupply::get(), 1000);
//         assert_eq!(PoolBalance::get(), 10);
//         let sn_list = SNList::get();
//         assert_eq!(sn_list.len(), 1);
//         assert_eq!(sn_list[0].as_ref(), old_sn_vec);

//     });
// }
