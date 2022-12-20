use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use cellpool_proofs::State;
use std::sync::Mutex;

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

struct AppState {
    state: Mutex<State>, // <- Mutex is necessary to mutate safely across threads
}

#[get("/dump")]
async fn index(data: web::Data<AppState>) -> String {
    let state = data.state.lock().unwrap(); // <- get counter's MutexGuard

    format!("Request number: {state:?}") // <- response with count
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
    let state = web::Data::new(AppState {
        state: Mutex::new(State::new(32)),
    });

    HttpServer::new(move || {
        App::new()
            .service(hello)
            .service(echo)
            .service(index)
            .app_data(state.clone()) // <- register the created data
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
