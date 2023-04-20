//!
//! The psuedocode on Wikipedia should be enough. HMAC is very easy.
//!
//! Using the web framework of your choosing (Sinatra, web.py, whatever), write a tiny application
//! that has a URL that takes a "file" argument and a "signature" argument, like so:
//!
//! http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
//!
//! Have the server generate an HMAC key, and then verify that the "signature" on incoming requests
//! is valid for "file", using the "==" operator to compare the valid MAC for a file with the
//! "signature" parameter (in other words, verify the HMAC the way any normal programmer would
//! verify it).
//!
//! Write a function, call it "insecure_compare", that implements the == operation by doing
//! byte-at-a-time comparisons with early exit (ie, return false at the first non-matching byte).
//!
//! In the loop for "insecure_compare", add a 50ms sleep (sleep 50ms after each byte).
//!
//! Use your "insecure_compare" function to verify the HMACs on incoming requests, and test that
//! the whole contraption works. Return a 500 if the MAC is invalid, and a 200 if it's OK.
//!
//! Using the timing leak in this application, write a program that discovers the valid MAC for any
//! file.
//!
//! ### Why artificial delays?
//!
//! Early-exit string compares are probably the most common source of cryptographic timing leaks,
//! but they aren't especially easy to exploit. In fact, many timing leaks (for instance, any in
//! C, C++, Ruby, or Python) probably aren't exploitable over a wide-area network at all. To play
//! with attacking real-world timing leaks, you have to start writing low-level timing code. We're
//! keeping things cryptographic in these challenges.

use actix_web::{get, web, App, HttpResponse, HttpServer, ResponseError};
use crypto::hash::to_hex;
use std::fmt::{Display, Formatter};
use std::{thread, time};

#[get("/test")]
async fn verify_signature(
    query: web::Query<SignatureQuery>,
) -> Result<HttpResponse, SignatureError> {
    let hmac_key = b"some-secret-key";
    let mac = "";
    let expected_signature = to_hex(mac.as_bytes());
    if insecure_compare(&query.signature, expected_signature.as_bytes()) {
        Ok(HttpResponse::Ok().body("OK"))
    } else {
        Err(SignatureError::InvalidSignature)
    }
}

fn insecure_compare(a: &str, b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (byte_a, byte_b) in a.bytes().zip(b.iter()) {
        if byte_a != *byte_b {
            return false;
        }
        thread::sleep(time::Duration::from_millis(50));
    }
    true
}

#[derive(serde::Deserialize)]
struct SignatureQuery {
    file: String,
    signature: String,
}

#[derive(Debug)]
enum SignatureError {
    InvalidSignature,
}

impl Display for SignatureError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid signature")
    }
}

impl ResponseError for SignatureError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(verify_signature))
        .bind("127.0.0.1:9000")?
        .run()
        .await
}

#[cfg(test)]
mod tests {
    use crate::ex_31_implement_and_break_hmac_sha1_with_an_artificial_timing_leak::verify_signature;
    use actix_web::http::header::ContentType;
    use actix_web::{test, web, App};

    #[actix_web::test]
    async fn test_index_get() {
        let app = test::init_service(App::new().service(verify_signature)).await;
        let req = test::TestRequest::default()
            .insert_header(ContentType::plaintext())
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
}
