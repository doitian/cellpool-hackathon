use actix_web::web::Json;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
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

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

async fn manual_hello() -> impl Responder {
    HttpResponse::Ok().body("Hey there!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let app_state = web::Data::new(StateData {
        state: Mutex::new(State::new()),
        uncommitted_transactions: Mutex::new(Vec::new()),
    });

    HttpServer::new(move || {
        App::new()
            .service(hello)
            .service(echo)
            .service(state_handler)
            .service(uncommitted_transactions_handler)
            .app_data(app_state.clone()) // <- register the created data
            .route("/hey", web::get().to(manual_hello))
    })
    .bind(("127.0.0.1", 5060))?
    .run()
    .await
}

// Initialize state
// Catchup
// rollup
// verify
