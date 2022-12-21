use crate::ledger::{AccRoot, State, StateError};
use crate::rollup::Rollup;
use crate::serde::SerdeAsBase64;

use crate::transaction::{get_transactions_hash, SignedTransaction, Transaction};
use crate::ConstraintF;
use ark_bls12_381::Bls12_381;
use ark_groth16::Groth16;
use ark_serialize::*;
use ark_snark::SNARK;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct Proof {
    #[serde_as(as = "SerdeAsBase64")]
    proof: ark_groth16::Proof<Bls12_381>,
    #[serde_as(as = "SerdeAsBase64")]
    vk: <Groth16<Bls12_381> as SNARK<ConstraintF>>::VerifyingKey,
}

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("Unable to rollup transactions: {0}")]
    Rollup(StateError),
    #[error("Underlying proving engine error: {0}")]
    ProvingEngine(ark_relations::r1cs::SynthesisError),
}

pub fn rollup_and_prove_mut(
    state: &mut State,
    transactions: &[SignedTransaction],
) -> Result<Proof, ProofError> {
    let rollup = state
        .rollup_transactions_mut(transactions, true)
        .map_err(ProofError::Rollup)?;

    generate_proof_from_rollup(&rollup)
}

pub fn rollup_and_prove(
    state: &State,
    transactions: &[SignedTransaction],
) -> Result<(State, Proof), ProofError> {
    let mut temp_state = state.clone();
    rollup_and_prove_mut(&mut temp_state, transactions).map(|proof| (temp_state, proof))
}

pub fn generate_proof_from_rollup(rollup: &Rollup) -> Result<Proof, ProofError> {
    let mut rng = ark_std::test_rng();
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(rollup, &mut rng)
        .map_err(ProofError::ProvingEngine)?;

    let proof = Groth16::prove(&pk, rollup, &mut rng).map_err(ProofError::ProvingEngine)?;
    Ok(Proof { proof, vk })
}

pub fn verify_proof_with_transactions(
    proof: &Proof,
    initial_root: &AccRoot,
    final_root: &AccRoot,
    transactions: &[Transaction],
) -> Result<bool, ProofError> {
    let public_inputs = get_public_inputs(initial_root, final_root, transactions);
    Groth16::verify(&proof.vk, &public_inputs, &proof.proof).map_err(ProofError::ProvingEngine)
}

pub fn verify_proof_with_transactions_hash(
    proof: &Proof,
    initial_root: &AccRoot,
    final_root: &AccRoot,
    transactions_hash: &[u8; 32],
) -> Result<bool, ProofError> {
    let public_inputs =
        get_public_inputs_from_transactions_hash(initial_root, final_root, transactions_hash);
    Groth16::verify(&proof.vk, &public_inputs, &proof.proof).map_err(ProofError::ProvingEngine)
}

pub(crate) fn get_public_inputs_from_transactions_hash(
    initial_root: &AccRoot,
    final_root: &AccRoot,
    transactions_hash: &[u8; 32],
) -> Vec<ConstraintF> {
    use ark_ff::ToConstraintField;
    let transaction_fields: Vec<ConstraintF> = transactions_hash.to_field_elements().unwrap();
    let mut result = Vec::with_capacity(transaction_fields.len() + 2);
    result.push(initial_root.clone());
    result.push(final_root.clone());
    result.extend(transaction_fields);
    result
}

pub(crate) fn get_public_inputs(
    initial_root: &AccRoot,
    final_root: &AccRoot,
    transactions: &[Transaction],
) -> Vec<ConstraintF> {
    get_public_inputs_from_transactions_hash(
        initial_root,
        final_root,
        &get_transactions_hash(transactions),
    )
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::ledger::{Amount, Parameters, State};

    fn build_n_transactions(
        n: usize,
        is_legal_transaction: bool,
    ) -> (State, Vec<Transaction>, Vec<SignedTransaction>) {
        use ark_std::rand::Rng;
        let mut rng = ark_std::test_rng();
        let pp = Parameters::sample(&mut rng);
        let mut state = State::new_with_parameters(&pp);
        // Let's make an account for Alice.
        let (alice_id, alice_pk, alice_sk) = state.sample_keys_and_register(&mut rng).unwrap();
        // Let's make an account for Bob.
        let (_bob_id, bob_pk, _bob_sk) = state.sample_keys_and_register(&mut rng).unwrap();

        let mut alice_balance = 0;
        let mut txs = Vec::with_capacity(n);
        let mut signed_txs = Vec::with_capacity(n);
        for _ in 0..n {
            let amount = rng.gen_range(10..20);
            alice_balance += amount;
            let signed_tx = SignedTransaction::create(
                &pp,
                alice_pk,
                bob_pk,
                Amount(amount),
                &alice_sk,
                &mut rng,
            );
            txs.push(Transaction::from(&signed_tx));
            signed_txs.push(signed_tx);
        }

        if is_legal_transaction {
            alice_balance += rng.gen_range(10..20);
        } else {
            alice_balance -= rng.gen_range(1..5);
        }
        state
            .update_balance_by_id(&alice_id, Amount(alice_balance))
            .expect("Alice's account should exist");

        (state, txs, signed_txs)
    }

    #[test]
    fn prove_and_verify_normal_transactions() {
        let (mut state, txs, signed_txs) = build_n_transactions(10, true);

        let initial_root = state.current_root();
        let proof = rollup_and_prove_mut(&mut state, &signed_txs).expect("Must create proof");

        let final_root = state.current_root();
        let is_valid_proof =
            verify_proof_with_transactions_hash(&proof, &initial_root, &final_root, &txs)
                .expect("Must verify proof");
        assert!(is_valid_proof);
    }

    #[test]
    fn prove_generation_on_illegal_transactions() {
        let (mut state, _txs, signed_txs) = build_n_transactions(5, false);

        let proof = rollup_and_prove_mut(&mut state, &signed_txs);
        assert!(proof.is_err());
    }
}
