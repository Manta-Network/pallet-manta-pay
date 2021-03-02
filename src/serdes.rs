use crate::param::*;
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::io::{Read, Write};
use sp_std::vec::Vec;

pub fn hash_param_serialize<W: Write>(hash_param: &HashParam, mut writer: W) {
    for generaters in hash_param.generators.iter() {
        for gen in generaters {
            gen.serialize_uncompressed(&mut writer).unwrap()
        }
    }
}

pub fn hash_param_deserialize<R: Read>(mut reader: R) -> HashParam {
    let window = PERDERSON_WINDOW_SIZE;
    let len = PERDERSON_WINDOW_NUM;

    let mut generators = Vec::new();
    for _ in 0..len {
        let mut gen = Vec::new();
        for _ in 0..window {
            gen.push(EdwardsProjective::deserialize_uncompressed(&mut reader).unwrap())
        }
        generators.push(gen);
    }

    HashParam { generators }
}

pub fn commit_param_serialize<W: Write>(com_param: &MantaCoinCommitmentParam, mut writer: W) {
    for generaters in com_param.generators.iter() {
        for gen in generaters {
            gen.serialize_uncompressed(&mut writer).unwrap()
        }
    }
    for rgen in com_param.randomness_generator.iter() {
        rgen.serialize_uncompressed(&mut writer).unwrap()
    }
}

pub fn commit_param_deserialize<R: Read>(mut reader: R) -> MantaCoinCommitmentParam {
    let window = PERDERSON_WINDOW_SIZE;
    let len = PERDERSON_WINDOW_NUM;

    let mut generators = Vec::new();
    for _ in 0..len {
        let mut gen = Vec::new();
        for _ in 0..window {
            gen.push(EdwardsProjective::deserialize_uncompressed(&mut reader).unwrap())
        }
        generators.push(gen);
    }
    let mut randomness_generator = Vec::new();
    for _ in 0..252 {
        randomness_generator.push(EdwardsProjective::deserialize_uncompressed(&mut reader).unwrap())
    }

    MantaCoinCommitmentParam {
        generators,
        randomness_generator,
    }
}
