#[macro_use]
extern crate criterion;
extern crate pallet_manta_dap;

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::CommitmentScheme;
use ark_crypto_primitives::FixedLengthCRH;
use ark_ed_on_bls12_381::Fq;
use ark_groth16::{create_random_proof, generate_random_parameters};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::ConstraintSystem;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use criterion::Benchmark;
use criterion::Criterion;
use pallet_manta_dap::forfeit::*;
use pallet_manta_dap::manta_token::*;
use pallet_manta_dap::param::*;
use pallet_manta_dap::priv_coin::*;
use pallet_manta_dap::transfer::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;

criterion_group!(manta_bench, bench_zkp_verify);
criterion_main!(manta_bench);

fn bench_zkp_verify(c: &mut Criterion) {
    let hash_param_seed = pallet_manta_dap::param::HASHPARAMSEED;
    let commit_param_seed = pallet_manta_dap::param::COMMITPARAMSEED;

    let mut rng = ChaCha20Rng::from_seed(commit_param_seed);
    let commit_param = MantaCoinCommitmentScheme::setup(&mut rng).unwrap();

    let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
    let hash_param = Hash::setup(&mut rng).unwrap();

    let (transfer_key_bytes, _forfeit_key_bytes) =
        manta_zkp_key_gen(&hash_param_seed, &commit_param_seed);
    let pk = Groth16PK::deserialize(transfer_key_bytes.as_ref()).unwrap();

    // sender
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);
    let (sender, sender_pub_info, sender_priv_info) =
        make_coin(&commit_param_seed, sk, 100, &mut rng);

    // receiver
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);
    let (receiver, receiver_pub_info, _receiver_priv_info) =
        make_coin(&commit_param_seed, sk, 100, &mut rng);

    let circuit = TransferCircuit {
        commit_param,
        hash_param,
        sender_coin: sender.clone(),
        sender_pub_info: sender_pub_info.clone(),
        sender_priv_info: sender_priv_info.clone(),
        receiver_coin: receiver.clone(),
        receiver_pub_info: receiver_pub_info.clone(),
        list: Vec::new(),
    };

    let sanity_cs = ConstraintSystem::<Fq>::new_ref();
    circuit
        .clone()
        .generate_constraints(sanity_cs.clone())
        .unwrap();
    assert!(sanity_cs.is_satisfied().unwrap());

    let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();
    let mut proof_bytes = [0u8; 192];
    proof.serialize(proof_bytes.as_mut()).unwrap();

    let bench_str = format!("ZKP verification");
    let bench = Benchmark::new(bench_str, move |b| {
        b.iter(|| {
            assert!(manta_verify_transfer_zkp(
                pallet_manta_dap::param::TRANSFERVKBYTES.to_vec(),
                proof_bytes,
                sender_priv_info.sn,
                sender_pub_info.k,
                receiver_pub_info.k,
                receiver.cm_bytes,
                [0u8; 32],
            ))
        })
    });

    // let bench = bench.warm_up_time(Duration::from_millis(1000));
    // let bench = bench.measurement_time(Duration::from_millis(5000));
    let bench = bench.sample_size(10);
    c.bench("manta_bench", bench);
}

#[allow(dead_code)]
fn manta_zkp_key_gen(
    hash_param_seed: &[u8; 32],
    commit_param_seed: &[u8; 32],
) -> (Vec<u8>, Vec<u8>) {
    // rebuild the parameters from the inputs
    let mut rng = ChaCha20Rng::from_seed(*commit_param_seed);
    let commit_param = MantaCoinCommitmentScheme::setup(&mut rng).unwrap();

    let mut rng = ChaCha20Rng::from_seed(*hash_param_seed);
    let hash_param = Hash::setup(&mut rng).unwrap();

    // we build a mock ledger of 128 users with a default seed [3; 32]
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let mut coins = Vec::new();
    let mut pub_infos = Vec::new();
    let mut priv_infos = Vec::new();
    let mut ledger = Vec::new();

    for e in 0..128 {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);

        let (coin, pub_info, priv_info) = make_coin(&commit_param_seed, sk, e + 100, &mut rng);

        ledger.push(coin.cm_bytes);
        coins.push(coin);
        pub_infos.push(pub_info);
        priv_infos.push(priv_info);
    }

    // sender
    let sender = coins[0].clone();
    let sender_pub_info = pub_infos[0].clone();
    let sender_priv_info = priv_infos[0].clone();

    // receiver
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);
    let (receiver, receiver_pub_info, _receiver_priv_info) =
        make_coin(&commit_param_seed, sk, 100, &mut rng);

    // transfer circuit
    let transfer_circuit = TransferCircuit {
        commit_param: commit_param.clone(),
        hash_param: hash_param.clone(),
        sender_coin: sender.clone(),
        sender_pub_info: sender_pub_info.clone(),
        sender_priv_info: sender_priv_info.clone(),
        receiver_coin: receiver,
        receiver_pub_info,
        list: ledger.clone(),
    };

    let sanity_cs = ConstraintSystem::<Fq>::new_ref();
    transfer_circuit
        .clone()
        .generate_constraints(sanity_cs.clone())
        .unwrap();
    assert!(sanity_cs.is_satisfied().unwrap());

    // transfer pk_bytes
    let mut rng = ChaCha20Rng::from_seed(ZKPPARAMSEED);
    let pk = generate_random_parameters::<Bls12_381, _, _>(transfer_circuit, &mut rng).unwrap();
    let mut transfer_pk_bytes: Vec<u8> = Vec::new();

    pk.serialize(&mut transfer_pk_bytes).unwrap();

    // forfeit circuit
    let forfeit_circuit = ForfeitCircuit {
        commit_param,
        hash_param,
        sender_coin: sender,
        sender_pub_info,
        sender_priv_info: sender_priv_info.clone(),
        value: sender_priv_info.value,
        list: ledger,
    };

    let sanity_cs = ConstraintSystem::<Fq>::new_ref();
    forfeit_circuit
        .clone()
        .generate_constraints(sanity_cs.clone())
        .unwrap();
    assert!(sanity_cs.is_satisfied().unwrap());

    // transfer pk_bytes
    let mut rng = ChaCha20Rng::from_seed(ZKPPARAMSEED);
    let pk = generate_random_parameters::<Bls12_381, _, _>(forfeit_circuit, &mut rng).unwrap();
    let mut forfeit_pk_bytes: Vec<u8> = Vec::new();
    pk.serialize(&mut forfeit_pk_bytes).unwrap();
    (transfer_pk_bytes, forfeit_pk_bytes)
}
