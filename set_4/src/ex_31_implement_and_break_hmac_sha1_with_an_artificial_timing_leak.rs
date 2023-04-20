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
use crypto::hash::{from_hex, to_hex};
use crypto::mac::hmac_sha1;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::time::Instant;
use std::{thread, time};

const FILE: &[u8] =
    b"Early-exit string compares are probably the most common source of cryptographic \
timing leaks, but they aren't especially easy to exploit. In fact, many timing leaks (for instance\
, any in C, C++, Ruby, or Python) probably aren't exploitable over a wide-area network at all. \
To play with attacking real-world timing leaks, you have to start writing low-level timing code. \
We're keeping things cryptographic in these challenges. ";

const HMAC_KEY: &[u8] = b"some-secret-key";

const LIMIT_FOR_TESTING: usize = 3;

#[get("/test")]
async fn verify_signature(
    query: web::Query<SignatureQuery>,
) -> Result<HttpResponse, SignatureError> {
    let mut mac = hmac_sha1(HMAC_KEY, &FILE);

    // REMOVE ME: just for faster testing
    mac.truncate(LIMIT_FOR_TESTING);
    // -----

    let expected_signature = &mac;
    if insecure_compare(&from_hex(&query.signature).unwrap(), expected_signature) {
        Ok(HttpResponse::Ok().body("OK"))
    } else {
        Err(SignatureError::InvalidSignature)
    }
}

fn insecure_compare(a: &[u8], b: &[u8]) -> bool {
    for (byte_a, byte_b) in a.into_iter().zip(b.iter()) {
        if *byte_a != *byte_b {
            return false;
        }
        thread::sleep(time::Duration::from_millis(50));
    }
    a.len() == b.len()
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
use std::pin::Pin;

async fn find_hmac<F>(sender: F) -> Vec<u8>
where
    F: Fn(Vec<u8>) -> Pin<Box<dyn Future<Output = bool>>>,
{
    let mut mac = hmac_sha1(HMAC_KEY, &FILE);
    mac.truncate(LIMIT_FOR_TESTING);

    let mut current_hmac = Vec::new();
    loop {
        let current_len = current_hmac.len();
        for i in 0..=255u8 {
            let mut buf = current_hmac.clone();
            buf.push(i);
            let start = Instant::now();
            // Call your function here
            let ret = sender(buf.clone()).await;
            if ret {
                if mac.len() != buf.len() {
                    panic!("Something weird happened");
                }
                return buf;
            }
            let duration = start.elapsed();
            if duration.as_millis() > (49 * buf.len()) as u128 {
                current_hmac.push(i);
                break;
            }
        }
        if current_hmac.len() == current_len {
            panic!(
                "Failed to find next byte:{:?}, len: {}",
                current_hmac, current_len
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ex_31_implement_and_break_hmac_sha1_with_an_artificial_timing_leak::{
        find_hmac, verify_signature, FILE, HMAC_KEY, LIMIT_FOR_TESTING,
    };
    use actix_web::http::header::ContentType;
    use actix_web::{test, App};
    use crypto::hash::to_hex;
    use crypto::mac::hmac_sha1;

    #[actix_web::test]
    async fn test_index_get() {
        let mut mac = hmac_sha1(HMAC_KEY, &FILE);
        mac.truncate(LIMIT_FOR_TESTING);

        let ret = find_hmac(move |buf| {
            Box::pin(async move {
                let app = test::init_service(App::new().service(verify_signature)).await;
                let req = test::TestRequest::default()
                    .uri(&format!("/test?file=foo&signature={}", to_hex(buf)))
                    .insert_header(ContentType::plaintext())
                    .to_request();
                test::call_service(&app, req).await.status().is_success()
            })
        })
        .await;

        assert_eq!(ret, mac);
    }
}
