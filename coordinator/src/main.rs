use actix_web::web::Json;
use actix_web::{error, get, post, web, App, HttpResponse, HttpServer, Responder};
use cellpool_proofs::ledger::StateError;
use cellpool_proofs::rollup::Rollup;
use cellpool_proofs::SignedTransaction;
use cellpool_proofs::State;
use std::sync::Mutex;

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
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
async fn rollup_handler(data: web::Data<StateData>) -> Result<Json<Rollup>, actix_web::Error> {
    let mut uncommitted_transactions = data.uncommitted_transactions.lock().unwrap();
    let mut state = data.state.lock().unwrap();
    let result = state.rollup_transactions_mut(&uncommitted_transactions, false);
    *uncommitted_transactions = vec![];
    result
        .map(Json)
        .map_err(|err| error::ErrorBadRequest(err.to_string()))
}

#[post("/rollup_transactions")]
async fn rollup_transactions_handler(
    data: web::Data<StateData>,
    transactions: Json<Vec<SignedTransaction>>,
) -> Result<Json<Rollup>, actix_web::Error> {
    let mut state = data.state.lock().unwrap();
    let result = state.rollup_transactions_mut(&transactions, false);
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
            .app_data(app_state.clone()) // <- register the created data
    })
    .bind(("127.0.0.1", 5060))?
    .run()
    .await
}

// Initialize state
// Catchup
// rollup
// verify
