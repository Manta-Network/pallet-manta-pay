#[macro_use]
extern crate criterion;
extern crate pallet_manta_dap;

use ark_crypto_primitives::CommitmentScheme;
use ark_crypto_primitives::FixedLengthCRH;
use ark_ed_on_bls12_381::Fq;
use ark_groth16::create_random_proof;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::ConstraintSystem;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use criterion::Benchmark;
use criterion::Criterion;
use pallet_manta_dap::manta_token::*;
use pallet_manta_dap::param::*;
use pallet_manta_dap::priv_coin::*;
use pallet_manta_dap::transfer::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;
use std::fs::File;
use std::io::prelude::*;

criterion_group!(manta_bench, bench_zkp_verify);
criterion_main!(manta_bench);

fn bench_zkp_verify(c: &mut Criterion) {
    let hash_param_seed = pallet_manta_dap::param::HASHPARAMSEED;
    let commit_param_seed = pallet_manta_dap::param::COMMITPARAMSEED;

    let mut rng = ChaCha20Rng::from_seed(commit_param_seed);
    let commit_param = MantaCoinCommitmentScheme::setup(&mut rng).unwrap();

    let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
    let hash_param = Hash::setup(&mut rng).unwrap();

    let mut file = File::open("transfer_pk.bin").unwrap();
    let mut transfer_key_bytes: Vec<u8> = vec![];
    file.read_to_end(&mut transfer_key_bytes).unwrap();

    let pk = Groth16PK::deserialize_uncompressed(transfer_key_bytes.as_ref()).unwrap();

    println!("proving key loaded from disk");

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
        hash_param: hash_param.clone(),
        sender_coin: sender.clone(),
        sender_pub_info: sender_pub_info.clone(),
        sender_priv_info: sender_priv_info.clone(),
        receiver_coin: receiver.clone(),
        receiver_pub_info: receiver_pub_info.clone(),
        list: vec![sender.cm_bytes],
    };

    let sanity_cs = ConstraintSystem::<Fq>::new_ref();
    circuit
        .clone()
        .generate_constraints(sanity_cs.clone())
        .unwrap();
    assert!(sanity_cs.is_satisfied().unwrap());

    println!("creating the proof");
    let proof = create_random_proof(circuit, &pk, &mut rng).unwrap();
    let mut proof_bytes = [0u8; 192];
    proof.serialize(proof_bytes.as_mut()).unwrap();

    let tree = LedgerMerkleTree::new(hash_param.clone(), &[sender.cm_bytes]).unwrap();
    let merkle_root = tree.root();
    let mut merkle_root_bytes = [0u8; 32];
    merkle_root.serialize(merkle_root_bytes.as_mut()).unwrap();

    println!("start benchmarking proof verification");
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
                merkle_root_bytes,
            ))
        })
    });

    // let bench = bench.sample_size(10);
    c.bench("manta_bench", bench);
}
