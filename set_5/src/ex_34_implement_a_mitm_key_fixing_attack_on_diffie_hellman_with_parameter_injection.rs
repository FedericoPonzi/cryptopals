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
//!
//! ------------
//! The code is not great, but it works:
//!   A sent me Hello, world!!
//!   B sent me Hello, world!!
//!   Protocol completed.

use crate::ex_33_implement_diffie_hellman::{generate_pk, generate_session_key};
use crate::{get_g, get_p};
use num_bigint::BigUint;
use crate::ex_34_implement_a_mitm_key_fixing_attack_on_diffie_hellman_with_parameter_injection::Message::{EncryptedMsg, EndOfProtocol, PublicKey};

#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Clone)]
pub enum Message {
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
pub struct Node {
    keys: Option<(BigUint, u32)>,
    session: Option<BigUint>,
    exchanged_messages: Vec<String>,
}
impl Node {
    pub fn new() -> Self {
        Node {
            session: None,
            keys: None,
            exchanged_messages: vec![],
        }
    }
    pub fn new_w_keys() -> Self {
        Node {
            session: None,
            keys: Some(generate_pk(&get_p(), &get_g())),
            exchanged_messages: vec![],
        }
    }
    pub fn new_w_keys_with_group(group: BigUint) -> Self {
        Node {
            session: None,
            keys: Some(generate_pk(&get_p(), &group)),
            exchanged_messages: vec![],
        }
    }
    pub fn handle_msg(&mut self, msg: Message) -> Message {
        match msg {
            PublicKey {
                p,
                g,
                other_public_key,
            } => self.receive_pk(p, g, other_public_key),
            Message::EncryptedMsg { iv, ct } => {
                let msg = self.recv_msg(iv, ct);
                if self.exchanged_messages.len() == 1 {
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
    pub fn private_key(&self) -> u32 {
        self.keys.clone().unwrap().1
    }
    pub fn public_key(&self) -> BigUint {
        self.keys.clone().unwrap().0
    }
    pub fn receive_pk(&mut self, p: BigUint, g: BigUint, other_public_key: BigUint) -> Message {
        if self.session.is_some() {
            self.exchanged_messages.push("Hello, world!".to_string());
            return self.send_msg("Hello, world!".to_string());
        }
        if self.keys.is_none() {
            self.keys = Some(generate_pk(&p, &g));
        }
        self.session =
            generate_session_key(self.keys.clone().unwrap().1, &other_public_key, &p).into();
        PublicKey {
            p,
            g,
            other_public_key: self.public_key(),
        }
    }
    pub fn send_msg(&self, msg: String) -> Message {
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
    pub fn recv_msg(&mut self, iv: [u8; 16], ct: Vec<u8>) -> String {
        let mut key = [0u8; 16];
        key.copy_from_slice(
            &crypto::hash::sha1::sha1(&self.session.clone().unwrap().to_bytes_be())[..16],
        );
        let msg = crypto::Pkcs7::remove_padding_unchecked(crypto::aes::cbc::decrypt_with_iv(
            &iv, &key, &ct,
        ));
        let msg = String::from_utf8(msg).unwrap();
        //println!("Received: {}", msg);
        self.exchanged_messages.push(msg.clone());
        msg
    }
}
struct Mitm {
    node_a: Node,
    node_b: Node,
}
impl Mitm {
    fn new() -> Self {
        Mitm {
            node_a: Node::new(),
            node_b: Node::new_w_keys(),
        }
    }
    fn handle_message(
        &mut self,
        msg: Message,
        sender: String,
    ) -> (Option<Message>, Option<Message>) {
        match msg {
            PublicKey {
                p,
                g,
                other_public_key,
            } => {
                (if sender == "a" {
                    (
                        Some(self.node_a.receive_pk(p, g, other_public_key)),
                        Some(self.node_b.send_pk()),
                    )
                } else {
                    (None, Some(self.node_b.receive_pk(p, g, other_public_key)))
                })
            }
            Message::EncryptedMsg { iv, ct } => {
                if sender == "a" {
                    let msg = self.node_a.recv_msg(iv, ct);
                    println!("A sent me {}!", msg);
                    (None, Some(self.node_b.send_msg(msg)))
                } else {
                    let msg = self.node_b.recv_msg(iv, ct);
                    println!("B sent me {}!", msg);
                    (Some(self.node_a.send_msg(msg)), None)
                }
            }
            Message::EndOfProtocol => {
                if sender == "a" {
                    (None, Some(EndOfProtocol))
                } else {
                    (Some(EndOfProtocol), None)
                }
            }
        }
    }
}

fn solve() {
    let mut a = Node::new_w_keys();
    let mut b = Node::new();
    let mut mitm = Mitm::new();
    // setup keys:
    let mut msg_to_b = a.send_pk();
    let (msg_to_a, msg_to_b) = mitm.handle_message(msg_to_b, "a".to_string());
    let msg_b = b.handle_msg(msg_to_b.unwrap());
    mitm.handle_message(msg_b, "b".to_string());
    let msg_to_b = a.handle_msg(msg_to_a.clone().unwrap());
    // will send msg because session is setted up:
    let msg_to_b = a.handle_msg(msg_to_a.unwrap());

    // send msg from a -> b
    let (msg_to_a, msg_to_b) = mitm.handle_message(msg_to_b, "a".to_string());
    assert!(msg_to_a.is_none());
    // b responds with something
    let msg_b = b.handle_msg(msg_to_b.unwrap());
    let (msg_to_a, msg_to_b) = mitm.handle_message(msg_b, "b".to_string());
    assert!(msg_to_b.is_none());
    let msg_to_b = a.handle_msg(msg_to_a.unwrap());

    // protocol is over, so a sends EndOfProtocol
    assert_eq!(msg_to_b, EndOfProtocol);
    let (msg_to_a, msg_to_b) = mitm.handle_message(msg_to_b, "a".to_string());
    assert!(msg_to_a.is_none());
    let msg_to_a = b.handle_msg(msg_to_b.unwrap());
    assert!(msg_to_a == EndOfProtocol);
    let (msg_to_a, msg_to_b) = mitm.handle_message(msg_to_a, "b".to_string());
    assert_eq!(msg_to_a.clone().unwrap(), EndOfProtocol);
    let msg = a.handle_msg(msg_to_a.unwrap()); // sends response back to a
    assert_eq!(msg, EndOfProtocol);
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
