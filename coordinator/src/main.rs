use actix_web::web::Json;
use actix_web::{error, get, post, web, App, HttpServer};
use cellpool_proofs::rollup::Rollup;
use cellpool_proofs::serde::SerdeAsHex;
use cellpool_proofs::{
    generate_proof_from_rollup, get_transactions_hash, rollup_and_prove, rollup_and_prove_mut,
    verify_proof_with_transactions_hash, AccRoot, State, Transaction,
};
use cellpool_proofs::{Proof, SignedTransaction};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::sync::Mutex;

#[derive(Debug, Serialize, Deserialize)]
struct Parameters {
    commit: Option<bool>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
struct ProofResult {
    proof: Proof,
    #[serde_as(as = "SerdeAsHex")]
    initial_root: AccRoot,
    #[serde_as(as = "SerdeAsHex")]
    final_root: AccRoot,
    #[serde_as(as = "Option<serde_with::hex::Hex>")]
    transactions_hash: Option<[u8; 32]>,
    transactions: Option<Vec<Transaction>>,
}

impl Parameters {
    fn should_commit(&self) -> bool {
        Some(true) == self.commit
    }
}

struct StateData {
    state: Mutex<State>, // <- Mutex is necessary to mutate safely across threads
    uncommitted_transactions: Mutex<Vec<SignedTransaction>>, // <- Mutex is necessary to mutate safely across threads
}

#[get("/state")]
async fn state_handler(data: web::Data<StateData>) -> Json<State> {
    let state = data.state.lock().unwrap();
    let state = state.clone();
    Json(state)
}

#[get("/uncommitted_transactions")]
async fn uncommitted_transactions_handler(
    data: web::Data<StateData>,
) -> Json<Vec<SignedTransaction>> {
    let uncommitted_transactions = data.uncommitted_transactions.lock().unwrap();
    let uncommitted_transactions = uncommitted_transactions.clone();
    Json(uncommitted_transactions)
}

#[post("/create_transaction")]
async fn create_transaction_handler(
    data: web::Data<StateData>,
    transaction: Json<SignedTransaction>,
) -> Json<SignedTransaction> {
    let mut uncommitted_transactions = data.uncommitted_transactions.lock().unwrap();
    uncommitted_transactions.push(transaction.clone());
    Json(transaction.clone())
}

#[get("/rollup")]
async fn rollup_handler(
    data: web::Data<StateData>,
    parameters: web::Query<Parameters>,
) -> Result<Json<(State, Rollup)>, actix_web::Error> {
    let mut uncommitted_transactions = data.uncommitted_transactions.lock().unwrap();
    let mut state = data.state.lock().unwrap();
    let result = if parameters.should_commit() {
        state
            .rollup_transactions_mut(&uncommitted_transactions, false)
            .map(|rollup| (state.clone(), rollup))
    } else {
        state.rollup_transactions(&uncommitted_transactions, false)
    };
    // Maybe we also need to delete bad transaction on error, lest they hang out there
    // forever.
    if parameters.should_commit() {
        *uncommitted_transactions = vec![];
    }
    result
        .map(Json)
        .map_err(|err| error::ErrorBadRequest(err.to_string()))
}

#[post("/rollup_transactions")]
async fn rollup_transactions_handler(
    data: web::Data<StateData>,
    parameters: web::Query<Parameters>,
    transactions: Json<Vec<SignedTransaction>>,
) -> Result<Json<(State, Proof)>, actix_web::Error> {
    let mut state = data.state.lock().unwrap();
    let result = if parameters.should_commit() {
        rollup_and_prove_mut(&mut state, &transactions).map(|rollup| (state.clone(), rollup))
    } else {
        rollup_and_prove(&state, &transactions)
    };
    result
        .map(Json)
        .map_err(|err| error::ErrorBadRequest(err.to_string()))
}

#[post("/generate_proof_from_rollup")]
async fn generate_proof_from_rollup_handler(
    rollup: Json<Rollup>,
) -> Result<Json<ProofResult>, actix_web::Error> {
    let result = generate_proof_from_rollup(&rollup);
    result
        .map(|proof| ProofResult {
            proof,
            initial_root: rollup.initial_root.unwrap(),
            final_root: rollup.final_root.unwrap(),
            transactions_hash: Some(get_transactions_hash(rollup.transactions.as_ref().unwrap())),
            transactions: rollup.transactions.clone(),
        })
        .map(Json)
        .map_err(|err| error::ErrorBadRequest(err.to_string()))
}

#[post("/verify_proof")]
async fn verify_proof_handler(proof: Json<ProofResult>) -> Result<Json<bool>, actix_web::Error> {
    let transactions_hash: Option<[u8; 32]> = proof.transactions_hash.or(proof
        .transactions
        .as_ref()
        .map(|t| get_transactions_hash(t)));
    if transactions_hash.is_none() {
        return Err(error::ErrorBadRequest("Transactions hash not given"));
    }
    let transactions_hash = transactions_hash.unwrap();
    let result = verify_proof_with_transactions_hash(
        &proof.proof,
        &proof.initial_root,
        &proof.final_root,
        &transactions_hash,
    );
    result
        .map(Json)
        .map_err(|err| error::ErrorBadRequest(err.to_string()))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let state: State = serde_json::from_str(
        r#"{
  "merkle_tree_root": "43c0b4e4b9c44ab78831c363c047408fbd9ff6cbbbd9db33046fdafcafd94859",
  "num_of_accounts": 256,
  "accounts": [
    {
      "id": 1,
      "public_key": "2b12d19214076b3e62721f7dfd6a2fe73b3dbf9fb965a3868021e1235dfeda11",
      "balance": 9223372036854775807
    },
    {
      "id": 2,
      "public_key": "24d00ecdb96c97df68d2cbc8e5b92d2f766f64ac209df473347e4973da62d337",
      "balance": 10000
    },
    {
      "id": 3,
      "public_key": "6502b9fe0ff15d22b88638040af8cac3399177c2c7438184c669bddc7fa7a9be",
      "balance": 4242
    }
  ]
}"#,
    )
    .unwrap();
    let app_state = web::Data::new(StateData {
        state: Mutex::new(state),
        uncommitted_transactions: Mutex::new(Vec::new()),
    });

    HttpServer::new(move || {
        App::new()
            .service(state_handler)
            .service(uncommitted_transactions_handler)
            .service(create_transaction_handler)
            .service(rollup_transactions_handler)
            .service(rollup_handler)
            .service(generate_proof_from_rollup_handler)
            .service(verify_proof_handler)
            .app_data(app_state.clone()) // <- register the created data
    })
    .bind(("127.0.0.1", 5060))?
    .run()
    .await
}
