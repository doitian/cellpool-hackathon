// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, packed::*, prelude::*},
    debug,
    high_level::{load_cell_data, load_cell_lock, load_script, load_witness_args},
};

use crate::error::Error;

use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::crh::{
    injective_map::{PedersenCRHCompressor, TECompressor},
    pedersen, TwoToOneCRH,
};
use ark_ec::ProjectiveCurve;
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_groth16::{Groth16, Proof};
use ark_serialize::*;
use ark_snark::SNARK;
use ark_std::vec::Vec;
use blake2::{Blake2s, Digest};

type VerifyingKey = <Groth16<Bls12_381> as SNARK<Fr>>::VerifyingKey;
type TwoToOneHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, TwoToOneWindow>;
type AccRoot = <TwoToOneHash as TwoToOneCRH>::Output;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TwoToOneWindow;

// `WINDOW_SIZE * NUM_WINDOWS` = 2 * 256 bits = enough for hashing two outputs.
impl pedersen::Window for TwoToOneWindow {
    const WINDOW_SIZE: usize = 128;
    const NUM_WINDOWS: usize = 4;
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CellPoolWitness {
    proof: Proof<Bls12_381>,
    transactions: Vec<Transaction>,
}

#[derive(
    Hash,
    Eq,
    PartialEq,
    Copy,
    Clone,
    PartialOrd,
    Ord,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
)]
pub struct Amount(pub u64);
pub type AccountPublicKey = <EdwardsProjective as ProjectiveCurve>::Affine;

#[derive(Copy, Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Transaction {
    /// The account information of the sender.
    pub sender: AccountPublicKey,
    /// The account information of the recipient.
    pub recipient: AccountPublicKey,
    /// The amount being transferred from the sender to the receiver.
    pub amount: Amount,
    /// The fee being collected by the miner.
    pub fee: Amount,
}

impl Amount {
    pub fn to_bytes_le(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

impl Transaction {
    /// Convert the transaction information to bytes.
    pub fn to_bytes_le(&self) -> Vec<u8> {
        ark_ff::to_bytes![
            get_public_key_bytes(&self.sender),
            get_public_key_bytes(&self.recipient),
            self.amount.to_bytes_le(),
            self.fee.to_bytes_le()
        ]
        .unwrap()
    }
}

pub fn get_public_key_bytes(pk: &AccountPublicKey) -> Vec<u8> {
    let mut bytes = Vec::new();
    pk.serialize_uncompressed(&mut bytes)
        .expect("Must serialize public key");
    bytes
}

fn ro_evaluate(input: &[u8]) -> [u8; 32] {
    let mut h = Blake2s::new();
    h.update(input);
    let mut result = [0u8; 32];
    result.copy_from_slice(&h.finalize());
    result
}

fn load_final_root(script: &Script) -> Result<Vec<u8>, Error> {
    for i in 0.. {
        let lock = load_cell_lock(i, Source::Output)?;
        if lock.as_bytes() == script.as_bytes() {
            return load_cell_data(i, Source::Output).map_err(Into::into);
        }
    }

    Err(Error::NoFinalRoot)
}

pub fn get_transactions_hash(transactions: &[Transaction]) -> [u8; 32] {
    let mut hash_input = Vec::new();
    for transaction in transactions {
        hash_input.extend_from_slice(&transaction.to_bytes_le());
    }
    ro_evaluate(&hash_input)
}

fn get_public_inputs(
    initial_root: AccRoot,
    final_root: AccRoot,
    transactions: Vec<Transaction>,
) -> Vec<Fr> {
    use ark_ff::ToConstraintField;
    let transaction_fields: Vec<Fr> = get_transactions_hash(&transactions[..])
        .to_field_elements()
        .unwrap();
    let mut result = Vec::with_capacity(transaction_fields.len() + 2);
    result.push(initial_root);
    result.push(final_root);
    result.extend(transaction_fields);
    result
}

// args
// - vk: VerifyingKey<Bls12_381> https://github.com/arkworks-rs/groth16/blob/3464e7910093723481fb98326b040025c5669b58/src/data_structures.rs#L31
//
// input cell data: initial root (optional, default is empty root)
// output cell data: final root
// witness: proof and transaction hashes
pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    debug!("script args len is {:?}", args.len());

    // return an error if args is invalid
    if args.is_empty() {
        return Err(Error::EmptyArgs);
    }

    // 1. Load vk from args
    let vk = VerifyingKey::deserialize_uncompressed(&*args).unwrap();

    // 2. Setup inputs from input / output cell data and witness
    let initial_root_bytes = load_cell_data(0, Source::GroupInput)?;
    let initial_root = AccRoot::deserialize_uncompressed(&*initial_root_bytes).unwrap();
    let final_root_bytes = load_final_root(&script)?;
    let final_root = AccRoot::deserialize_uncompressed(&*final_root_bytes).unwrap();
    let witness_bytes: Vec<u8> = load_witness_args(0, Source::Input)
        .unwrap()
        .lock()
        .to_opt()
        .unwrap()
        .unpack();
    // debug!("witness is {:?}", witness_bytes);
    let witness = CellPoolWitness::deserialize_uncompressed(&*witness_bytes).unwrap();
    let proof = witness.proof;
    let transactions = witness.transactions;

    // 3. Run Groth16 to verify
    let public_inputs = get_public_inputs(initial_root, final_root, transactions);
    Groth16::verify(&vk, &public_inputs, &proof).unwrap();

    Ok(())
}
