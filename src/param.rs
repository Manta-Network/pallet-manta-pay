use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{
	commitment::pedersen::{constraints::CommGadget, Commitment, Window},
	crh::{
		pedersen::{constraints::CRHGadget, CRH},
		FixedLengthCRH, FixedLengthCRHGadget,
	},
	merkle_tree::{Config, Digest, Path},
	CommitmentScheme as ArkCommitmentScheme, MerkleTree, SNARK, *,
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsParameters, EdwardsProjective, Fq};
use ark_groth16::Groth16;
use ark_r1cs_std::{fields::fp::FpVar, groups::curves::twisted_edwards::AffineVar};

pub const ZKPPARAMSEED: [u8; 32] = [3u8; 32];
pub const HASHPARAMSEED: [u8; 32] = [1u8; 32];
pub const COMMITPARAMSEED: [u8; 32] = [2u8; 32];

//=======================
// pedersen hash and related defintions
// the hash function is defined over the JubJub curve
//=======================
pub(crate) const PERDERSON_WINDOW_SIZE: usize = 4;
pub(crate) const PERDERSON_WINDOW_NUM: usize = 256;

// #leaves = 2^{height - 1}
#[allow(dead_code)]
const MAX_ACC: usize = 1048576;
const MAX_ACC_TREE_DEPTH: usize = 21;

#[derive(Clone)]
pub struct PedersenWindow;
impl Window for PedersenWindow {
	const WINDOW_SIZE: usize = PERDERSON_WINDOW_SIZE;
	const NUM_WINDOWS: usize = PERDERSON_WINDOW_NUM;
}
pub type Hash = CRH<EdwardsProjective, PedersenWindow>;
#[allow(dead_code)]
pub(crate) type HashOutput = <Hash as FixedLengthCRH>::Output;
pub type HashParam = <Hash as FixedLengthCRH>::Parameters;

//=======================
// merkle tree for the ledger, using Perderson hash
//=======================
#[derive(Debug, Clone, Copy)]
pub struct MerkleTreeParams;
impl Config for MerkleTreeParams {
	const HEIGHT: usize = MAX_ACC_TREE_DEPTH;
	type H = Hash;
}
pub type LedgerMerkleTree = MerkleTree<MerkleTreeParams>;
#[allow(dead_code)]
pub type LedgerMerkleTreeRoot = Digest<MerkleTreeParams>;

// the membership is a path on the merkle tree, including the leaf itself
#[allow(dead_code)]
pub type AccountMembership = Path<MerkleTreeParams>;

//=======================
// Commitments
//=======================
pub type CommitmentScheme = Commitment<EdwardsProjective, PedersenWindow>;
pub type CommitmentParam = <CommitmentScheme as ArkCommitmentScheme>::Parameters;
#[allow(dead_code)]
pub(crate) type CommitmentOpen = <CommitmentScheme as ArkCommitmentScheme>::Randomness;
pub(crate) type CommitmentOutput = <CommitmentScheme as ArkCommitmentScheme>::Output;

// gadgets for hash function
pub(crate) type HashVar = CRHGadget<EdwardsProjective, EdwardsVar, PedersenWindow>;
pub(crate) type HashOutputVar = <HashVar as FixedLengthCRHGadget<Hash, Fq>>::OutputVar;
pub(crate) type HashParamVar = <HashVar as FixedLengthCRHGadget<Hash, Fq>>::ParametersVar;

// gadget for private coin account membership
#[allow(dead_code)]
pub(crate) type AccountMembershipVar = PathVar<MerkleTreeParams, HashVar, Fq>;

//=======================
// ZK proofs over BLS curve
//=======================
#[allow(dead_code)]
pub type Groth16PK = <Groth16<Bls12_381> as SNARK<Fq>>::ProvingKey;
#[allow(dead_code)]
pub type Groth16PVK = <Groth16<Bls12_381> as SNARK<Fq>>::ProcessedVerifyingKey;
#[allow(dead_code)]
pub type Groth16VK = <Groth16<Bls12_381> as SNARK<Fq>>::VerifyingKey;
pub type Groth16Proof = <Groth16<Bls12_381> as SNARK<Fq>>::Proof;

//=======================
// Commitments
//=======================
pub(crate) type CommitmentSchemeVar = CommGadget<EdwardsProjective, EdwardsVar, PedersenWindow>;
pub(crate) type CommitmentParamVar =
	<CommitmentSchemeVar as CommitmentGadget<CommitmentScheme, Fq>>::ParametersVar;
pub(crate) type MantaCoinCommitmentOpenVar =
	<CommitmentSchemeVar as CommitmentGadget<CommitmentScheme, Fq>>::RandomnessVar;
pub(crate) type MantaCoinCommitmentOutputVar = AffineVar<EdwardsParameters, FpVar<Fq>>;
