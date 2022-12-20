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
) -> Json<Vec<SignedTransaction>> {
    let mut uncommitted_transactions = data.uncommitted_transactions.lock().unwrap();
    uncommitted_transactions.push(transaction.clone());
    let uncommitted_transactions = uncommitted_transactions.clone();
    Json(uncommitted_transactions)
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
    let app_state = web::Data::new(StateData {
        state: Mutex::new(State::new()),
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
