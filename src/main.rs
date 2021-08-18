
pub mod models;
pub mod context;
pub mod jwt;
pub mod comm;
pub mod handlers;

pub mod legacy_login;
pub mod new_login;
pub mod thbwiki_login;
pub mod qq_binding;

use std::{cell::Cell, sync::Arc};

use actix_web::{web, App, HttpRequest, HttpServer, Responder};
use jwt::load_keys;
use mongodb::{Client, options::ClientOptions};

use redis::AsyncCommands;

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    let client_options = ClientOptions::parse("mongodb://mongo:27017").await.expect("Failed to parse MongoDB parameters");
	let client = Client::with_options(client_options).expect("Failed to connect to MongoDB");

	let db = client.database("thvote_users");

    let redis_client = redis::Client::open(comm::REDIS_ADDRESS).unwrap();

    let ctx = context::AppContext {
        vote_year: 2021,
        db: db.clone(),
        voters_coll: db.collection_with_type("voters"),
        redis_client: redis_client,
        key_pair: load_keys().await.unwrap(),
    };
    HttpServer::new(move || {
        App::new().data(ctx.clone())
            .route("/v1/login-email-password", web::post().to(handlers::login_email_password))
            .route("/v1/login-email", web::post().to(handlers::login_email))
            .route("/v1/login-phone", web::post().to(handlers::login_phone))
            .route("/v1/send-sms-code", web::post().to(handlers::send_phone_verify_code))
            .route("/v1/send-email-code", web::post().to(handlers::send_email_verify_code))
    })
    .bind(("0.0.0.0", 80))?
    .run()
    .await
}
