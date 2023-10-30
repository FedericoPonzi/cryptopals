//! ### Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
//!
//! Use the code you just worked out to build a protocol and an "echo" bot. You don't actually have to do the network part of this if you don't want; just simulate that. The protocol is:
//!
//! A->B
//!
//! Send "p", "g", "A"
//!
//! B->A
//!
//! Send "B"
//!
//! A->B
//!
//! Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
//!
//! B->A
//!
//! Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
//!
//! (In other words, derive an AES key from DH with SHA1, use it in both directions, and do CBC with random IVs appended or prepended to the message).
//!
//! Now implement the following MITM attack:
//!
//! A->M
//!
//! Send "p", "g", "A"
//!
//! M->B
//!
//! Send "p", "g", "p"
//!
//! B->M
//!
//! Send "B"
//!
//! M->A
//!
//! Send "p"
//!
//! A->M
//!
//! Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
//!
//! M->B
//!
//! Relay that to B
//!
//! B->M
//!
//! Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
//!
//! M->A
//!
//! Relay that to A
//!
//! M should be able to decrypt the messages. "A" and "B" in the protocol --- the public keys, over the wire --- have been swapped out with "p". Do the DH math on this quickly to see what that does to the predictability of the key.
//!
//! Decrypt the messages from M's vantage point as they go by.
//!
//! Note that you don't actually have to inject bogus parameters to make this attack work; you could just generate Ma, MA, Mb, and MB as valid DH parameters to do a generic MITM attack. But do the parameter injection attack; it's going to come up again.

use crate::ex_33_implement_diffie_hellman::{generate_pk, generate_session_key};
use crate::{get_g, get_p};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use rand::random;
use crate::ex_34_implement_a_mitm_key_fixing_attack_on_diffie_hellman_with_parameter_injection::Message::{EndOfProtocol, PublicKey};

struct Mitm {
    p: u64,
    g: u64,
    a: u64,
    b: u64,
}
#[derive(Ord, PartialOrd, Eq, PartialEq, Debug)]
enum Message {
    PublicKey {
        p: BigUint,
        g: BigUint,
        other_public_key: BigUint,
    },
    EncryptedMsg {
        iv: [u8; 16],
        ct: Vec<u8>,
    },
    EndOfProtocol,
}
struct Node {
    keys: Option<(BigUint, u32)>,
    session: Option<BigUint>,
    received_messages: Vec<String>,
}
impl Node {
    fn new() -> Self {
        Node {
            session: None,
            keys: None,
            received_messages: vec![],
        }
    }
    fn new_w_keys() -> Self {
        Node {
            session: None,
            keys: Some(generate_pk(&get_p(), &get_g())),
            received_messages: vec![],
        }
    }
    fn handle_msg(&mut self, msg: Message) -> Message {
        match msg {
            PublicKey {
                p,
                g,
                other_public_key,
            } => self.receive_pk(p, g, other_public_key),
            Message::EncryptedMsg { iv, ct } => {
                let msg = self.recv_msg(iv, ct);
                if self.received_messages.len() == 1 {
                    return self.send_msg(msg);
                } else {
                    return EndOfProtocol;
                }
            }
            Message::EndOfProtocol => {
                return EndOfProtocol;
            }
        }
    }
    pub fn send_pk(&self) -> Message {
        PublicKey {
            p: get_p(),
            g: get_g(),
            other_public_key: self.public_key(),
        }
    }
    fn private_key(&self) -> u32 {
        self.keys.clone().unwrap().1
    }
    fn public_key(&self) -> BigUint {
        self.keys.clone().unwrap().0
    }
    fn receive_pk(&mut self, p: BigUint, g: BigUint, other_public_key: BigUint) -> Message {
        if self.session.is_some() {
            return self.send_msg("Hello, world!".to_string());
        }
        if self.keys.is_none() {
            self.keys = Some(generate_pk(&p, &g));
        }
        self.session =
            generate_session_key(self.keys.clone().unwrap().1, &other_public_key, &p).into();
        println!("Session key: {:?}", self.session);
        PublicKey {
            p,
            g,
            other_public_key: self.public_key(),
        }
    }
    fn send_msg(&self, msg: String) -> Message {
        ///     Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
        let iv = crypto::aes::random_key();
        let mut key = [0u8; 16];
        key.copy_from_slice(
            &crypto::hash::sha1::sha1(&self.session.clone().unwrap().to_bytes_be())[..16],
        );
        let ct =
            crypto::aes::cbc::encrypt_with_iv(&iv, &key, &crypto::Pkcs7::pad_16(msg.as_bytes()));
        Message::EncryptedMsg { iv, ct }
    }
    fn recv_msg(&mut self, iv: [u8; 16], ct: Vec<u8>) -> String {
        let mut key = [0u8; 16];
        key.copy_from_slice(
            &crypto::hash::sha1::sha1(&self.session.clone().unwrap().to_bytes_be())[..16],
        );
        let msg = crypto::Pkcs7::remove_padding_unchecked(crypto::aes::cbc::decrypt_with_iv(
            &iv, &key, &ct,
        ));
        let msg = String::from_utf8(msg).unwrap();
        println!("Received: {}", msg);
        self.received_messages.push(msg.clone());
        msg
    }
}

fn solve() {
    let mut a = Node::new_w_keys();
    let mut b = Node::new();
    let mut msg = a.send_pk();
    while msg != EndOfProtocol {
        dbg!(&msg);
        msg = b.handle_msg(msg);
        dbg!(&msg);
        msg = a.handle_msg(msg);
    }
    println!("Protocol completed.");
}

#[cfg(test)]
mod tests {
    use crate::ex_34_implement_a_mitm_key_fixing_attack_on_diffie_hellman_with_parameter_injection::solve;

    #[test]
    fn test_solve() {
        solve();
    }
}
