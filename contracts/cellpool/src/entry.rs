// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::{vec, vec::Vec};

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
use ark_groth16::Groth16;
use ark_serialize::*;
use ark_snark::SNARK;

type VerifyingKey = <Groth16<Bls12_381> as SNARK<Fr>>::VerifyingKey;

fn load_final_root(script: &Script) -> Result<Vec<u8>, Error> {
    for i in 0.. {
        let lock = load_cell_lock(i, Source::Output)?;
        if lock.as_slice() == script.as_slice() {
            return load_cell_data(i, Source::Output).map_err(Into::into);
        }
    }

    Err(Error::NoFinalRoot)
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
    let initial_root = load_cell_data(0, Source::GroupInput)?;
    let final_root = load_final_root(&script)?;
    let witness_args = load_witness_args(0, Source::Input).unwrap();

    // 3. Run Groth16 to verify

    Ok(())
}
