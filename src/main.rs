
pub mod models;
pub mod context;
pub mod jwt;

pub mod legacy_login;
pub mod new_login;
pub mod thbwiki_login;
pub mod qq_binding;

use actix_web::{web, App, HttpRequest, HttpServer, Responder};
use mongodb::{Client, options::ClientOptions};

async fn greet(ctx: web::Data<context::AppContext>, req: HttpRequest) -> impl Responder {
    let name = req.match_info().get("name").unwrap_or("World");
    format!("{} {}!", "hello", &name)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    let client_options = ClientOptions::parse("mongodb://127.0.0.1:27017").await.expect("Failed to parse MongoDB parameters");
	let client = Client::with_options(client_options).expect("Failed to connect to MongoDB");

	let db = client.database("thvote_users");

    let ctx = context::AppContext {
        db: db.clone(),
        voters_coll: db.collection_with_type("voters")
    };
    HttpServer::new(move || {
        App::new().data(ctx.clone())
            .route("/", web::get().to(greet))
            .route("/{name}", web::get().to(greet))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}