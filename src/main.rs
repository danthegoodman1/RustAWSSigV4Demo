use actix_web::{App, error, Error, HttpRequest, HttpResponse, HttpServer, web};
use actix_web::http::StatusCode;
use std::str;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(index_manual))
            .route("/", web::post().to(index_manual))
            .default_service(web::route().to(catch_all))
    })
        .bind(("0.0.0.0", 8080))?
        .run()
        .await
}


const MAX_SIZE: usize = 262_144; // max payload size is 256k

async fn index_manual(body: web::Bytes) -> Result<HttpResponse, Error> {
    // body is loaded, now we can deserialize serde-json
    match str::from_utf8(&body) {
        Ok(body_str) => {
            // If successful, print the string
            println!("I got something: {}", body_str);
        }
        Err(e) => {
            // If conversion failed, print an error message
            println!("Error while converting body to string: {}", e);
        }
    }
    Ok(HttpResponse::Ok().body("hey")) // <- send response
}

async fn catch_all(req: HttpRequest) -> Result<HttpResponse, Error> {
    println!("Path: {}\nQuery String: {}\nHeaders:\n{}", req.path(), req.query_string(), req.headers().iter()
        .map(|(h, v)| format!("\t{}: {}", h.as_str(), v.to_str().unwrap_or("")))
        .collect::<Vec<_>>().join("\n"));
    Ok(HttpResponse::NotFound().body("not found boi"))
    // Ok(HttpResponse::Ok().status(StatusCode::from_u16(404).unwrap()).body("route not found"))
}