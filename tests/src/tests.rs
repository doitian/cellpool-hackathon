use super::*;

use ark_bls12_381::Bls12_381;
use ark_groth16::Groth16;
use ark_serialize::*;
use ark_snark::SNARK;
use cellpool_proofs::{
    ledger::{Amount, Parameters, State},
    rollup::Rollup,
    transaction::SignedTransaction,
};
use ckb_testtool::ckb_error::Error;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;

const MAX_CYCLES: u64 = 3_000_000_000;

// error numbers
const ERROR_EMPTY_ARGS: i8 = 5;

fn assert_script_error(err: Error, err_code: i8) {
    let error_string = err.to_string();
    assert!(
        error_string.contains(format!("error code {} ", err_code).as_str()),
        "error_string: {}, expected_error_code: {}",
        error_string,
        err_code
    );
}

// Builds a circuit with two txs, using different pubkeys & amounts every time.
// It returns this circuit
fn build_two_tx_circuit() -> Rollup {
    use ark_std::rand::Rng;
    let mut rng = ark_std::test_rng();
    let pp = Parameters::sample(&mut rng);
    let mut state = State::new_with_parameters(32, &pp);
    // Let's make an account for Alice.
    let (alice_id, alice_pk, alice_sk) = state.sample_keys_and_register(&mut rng).unwrap();
    // Let's give her some initial balance to start with.
    state
        .update_balance_by_id(&alice_id, Amount(1000))
        .expect("Alice's account should exist");
    // Let's make an account for Bob.
    let (_bob_id, bob_pk, _bob_sk) = state.sample_keys_and_register(&mut rng).unwrap();

    let amount_to_send = rng.gen_range(0..200);

    // Alice wants to transfer amount_to_send units to Bob, and does this twice
    let mut temp_state = state.clone();
    let tx1 = SignedTransaction::create(
        &pp,
        alice_pk,
        bob_pk,
        Amount(amount_to_send),
        &alice_sk,
        &mut rng,
    );

    temp_state.rollup_transactions(&[tx1], true, true).unwrap()
}

#[test]
fn test_success() {
    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("cellpool");
    let out_point = context.deploy_cell(contract_bin);

    let mut rng = ark_std::test_rng();
    // Use the same circuit but with different inputs to verify against
    // This test checks that the SNARK passes on the provided input
    let circuit_to_verify_against = build_two_tx_circuit();
    let (_, vk) =
        Groth16::<Bls12_381>::circuit_specific_setup(&circuit_to_verify_against, &mut rng).unwrap();
    let mut serialized_bytes = Vec::new();
    vk.serialize_uncompressed(&mut serialized_bytes).unwrap();

    // prepare scripts
    let lock_script = context
        .build_script(&out_point, Bytes::from(serialized_bytes.clone()))
        .expect("script");
    let lock_script_dep = CellDep::new_builder().out_point(out_point).build();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![CellOutput::new_builder()
        .capacity(1000u64.pack())
        .lock(lock_script.clone())
        .build()];

    let outputs_data = vec![Bytes::from(serialized_bytes)];

    let lock_witness = vec![0];
    let witness = WitnessArgsBuilder::default()
        .lock(
            BytesOptBuilder::default()
                .set(Some(lock_witness.pack()))
                .build(),
        )
        .build();

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .witness(witness.as_bytes().pack())
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(lock_script_dep)
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_empty_args() {
    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("cellpool");
    let out_point = context.deploy_cell(contract_bin);

    // prepare scripts
    let lock_script = context
        .build_script(&out_point, Default::default())
        .expect("script");
    let lock_script_dep = CellDep::new_builder().out_point(out_point).build();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![CellOutput::new_builder()
        .capacity(1000u64.pack())
        .lock(lock_script.clone())
        .build()];

    let outputs_data = vec![Bytes::new()];

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(lock_script_dep)
        .build();
    let tx = context.complete_tx(tx);

    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    assert_script_error(err, ERROR_EMPTY_ARGS);
}
