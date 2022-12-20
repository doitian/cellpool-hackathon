// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::{vec, vec::Vec};

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use ckb_std::{
    debug,
    high_level::{load_script, load_tx_hash},
    ckb_types::{bytes::Bytes, prelude::*},
};

use crate::error::Error;

use ark_serialize::*;
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;

type VerifyingKey = <Groth16<Bls12_381> as SNARK<Fr>>::VerifyingKey;

// args
// - vk: VerifyingKey<Bls12_381> https://github.com/arkworks-rs/groth16/blob/3464e7910093723481fb98326b040025c5669b58/src/data_structures.rs#L31
//
// input cell data: initial root (optional, default is empty root)
// output cell data: final root
// witness: proof and transaction hashes
pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    debug!("script args is {:?}", args);

    // return an error if args is invalid
    if args.is_empty() {
        return Err(Error::EmptyArgs);
    }

    // 1. Load vk from args
    let vk = VerifyingKey::deserialize_uncompressed(&*args).unwrap();

    // 2. Setup inputs from input / output cell data and witness
    // 3. Run Groth16 to verify

    Ok(())
}

