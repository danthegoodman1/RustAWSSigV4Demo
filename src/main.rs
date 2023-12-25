use std::collections::BTreeMap;
use std::fmt::Write;
use std::str;

use actix_web::{App, Error, HttpRequest, HttpResponse, HttpServer, web};
use anyhow;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use awc::{Client};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .app_data(web::Data::new(Client::default()))
            .route("/", web::get().to(proxy_request))
            .route("/", web::post().to(proxy_request))
            .default_service(web::route().to(catch_all))
    })
        .bind(("0.0.0.0", 8080))?
        .bind(("::1", 8080))?
        .run()
        .await
}


const MAX_SIZE: usize = 262_144;

// max payload size is 256k
type HmacSha256 = Hmac<Sha256>;

fn get_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize();
    result.into_bytes().to_vec()
    // -> anyhow::Result(Vec<u8>) {
    // let mut mac = match HmacSha256::new_from_slice(key) {
    //     Ok(m) => m,
    //     Err(e) => anyhow::anyhow!(e).context("HMAC can take key of any size")
    // };
    // mac.update(data);
    // let result = mac.finalize();
    // Ok(result.into_bytes().to_vec())
}

fn get_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn get_string_to_sign(req: &HttpRequest, canonical_request: &str) -> String {
    let mut s = String::from("AWS4-HMAC-SHA256\n");

    let x_amz_date = req.headers()
        .get("X-Amz-Date")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();

    s.push_str(x_amz_date);
    s.push('\n');

    let scope = format!("{}/{}/{}/{}", &x_amz_date[..8], "us-east-1", "dynamodb", "aws4_request");
    s.push_str(&scope);
    s.push('\n');

    let canonical_request_hash = get_sha256(canonical_request.as_bytes());
    let mut hex_encoded_hash = String::new();
    for byte in canonical_request_hash {
        write!(hex_encoded_hash, "{:02x}", byte).expect("Can write to a String");
    }

    s.push_str(&hex_encoded_hash);

    s
}

fn get_signing_key(req: &HttpRequest) -> Vec<u8> {
    let x_amz_date = req.headers()
        .get("X-Amz-Date")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();

    let date_key = get_hmac(b"AWS4testpassword", &x_amz_date[..8].as_bytes());
    let date_region_key = get_hmac(&date_key, b"us-east-1");
    let date_region_service_key = get_hmac(&date_region_key, b"dynamodb");
    let signing_key = get_hmac(&date_region_service_key, b"aws4_request");

    signing_key
}

fn get_canonical_request(req: &HttpRequest) -> Result<String, Error> {
    let mut canonical_request = String::new();

    // Add HTTP method
    canonical_request.push_str(req.method().as_str());
    canonical_request.push('\n');

    // Add the path
    canonical_request.push_str(req.uri().path());
    canonical_request.push('\n');

    // Add the encoded query string
    let query_string = req.uri().query().unwrap_or_default();
    canonical_request.push_str(query_string);
    canonical_request.push('\n');

    // Extract signed headers from Authorization
    let signed_headers: BTreeMap<_, _> = if let Some(auth_header) = req.headers().get("Authorization") {
        auth_header.to_str().expect("failed to parse auth header to string").split(", ")
            .find_map(|item| {
                if item.starts_with("SignedHeaders=") {
                    let headers = item.trim_start_matches("SignedHeaders=").replace(",", ";");
                    let header_list: Vec<_> = headers.split(';').collect();
                    let mut signed_header_values = BTreeMap::new();

                    // Iterate over signed headers and insert header names and values into the map
                    for header_name in header_list {
                        if req.headers().contains_key(header_name) {
                            let value = req.headers().get(header_name).unwrap().to_str().unwrap_or_default().trim().to_owned();
                            signed_header_values.insert(header_name.to_lowercase(), value);
                        }
                    }

                    Some(signed_header_values)
                } else {
                    None
                }
            })
            .unwrap_or_default()
    } else {
        BTreeMap::new()
    };

    // Add headers to canonical request
    for (header_name, header_value) in &signed_headers {
        canonical_request.push_str(header_name);
        canonical_request.push(':');
        canonical_request.push_str(header_value);
        canonical_request.push('\n');
    }

    // Add a newline separator
    canonical_request.push('\n');

    // Add signed headers names
    canonical_request.push_str(&signed_headers.keys().cloned().collect::<Vec<_>>().join(";"));
    canonical_request.push('\n');

    // Handle 'x-amz-content-sha256' header
    let sha_header = req.headers().get("x-amz-content-sha256").map_or_else(
        || "UNSIGNED-PAYLOAD".to_string(),
        |h| h.to_str().unwrap_or("UNSIGNED-PAYLOAD").to_owned(),
    );

    // Add the 'x-amz-content-sha256' value
    canonical_request.push_str(&sha_header);

    Ok(canonical_request)
}

fn extract_provided_signature(req: &HttpRequest) -> Option<String> {
    // Get the Authorization header as a string
    let authorization_header = req.headers().get("Authorization")?.to_str().ok()?;
    let parts: Vec<&str> = authorization_header.split(", ").collect();

    // Find the "Signature" part
    for item in parts {
        if item.starts_with("Signature") {
            return Some(item.split('=').nth(1)?.to_string());
        }
    }

    None
}

async fn index_manual(req: HttpRequest, body: web::Bytes) -> Result<HttpResponse, Error> {
    let canonical_request = get_canonical_request(&req)?;
    let string_to_sign = get_string_to_sign(&req, canonical_request.as_str());
    let signing_key = get_signing_key(&req);
    let signature = hex::encode(get_hmac(signing_key.as_slice(), string_to_sign.as_bytes()));
    let provided_signature = extract_provided_signature(&req).unwrap();
    println!("prov: {}", provided_signature);
    println!("mine: {}", signature);

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

async fn proxy_request(req: HttpRequest, body: web::Payload, client: web::Data<Client>) -> Result<HttpResponse, Error> {
    // let canonical_request = get_canonical_request(&req)?;
    // let string_to_sign = get_string_to_sign(&req, canonical_request.as_str());
    // let signing_key = get_signing_key(&req);
    // let signature = hex::encode(get_hmac(signing_key.as_slice(), string_to_sign.as_bytes()));
    // let provided_signature = extract_provided_signature(&req).unwrap();
    // println!("prov: {}", provided_signature);
    // println!("mine: {}", signature);

    // Define the URL you want to proxy to
    let url = "https://httpbin.org/anything";

    // Create the client request using the awc client
    let mut origin_req = client
        .request_from(url, req.head())
        .no_decompress(); // Disable auto-decompression

    // Copy headers from the incoming request
    for (header_name, header_value) in req.headers() {
        // Ignore host header
        if header_name == "host" {
            continue;
        }
        origin_req = origin_req.insert_header((header_name.clone(), header_value.clone()));
    }

    // Send the client request and wait for the response
    let mut response = origin_req
        .send_stream(body)
        .await
        .map_err(actix_web::error::ErrorServiceUnavailable)?;

    let mut client_response = HttpResponse::build(response.status());
    for (header_name, header_value) in response.headers() {
        client_response.append_header((header_name.clone(), header_value.clone()));
    }

    // Use the streaming body from the response.
    Ok(client_response.streaming(response))
}