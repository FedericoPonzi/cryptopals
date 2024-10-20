//!
//!
//! Implement DH with negotiated groups, and break with malicious "g" parameters
//!
//! A->B
//!     Send "p", "g"
//! B->A
//!     Send ACK
//! A->B
//!     Send "A"
//! B->A
//!     Send "B"
//! A->B
//!     Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
//! B->A
//!     Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
//!
//! Do the MITM attack again, but play with "g". What happens with:
//!
//!     g = 1
//!     g = p
//!     g = p - 1
//!
//! Write attacks for each.
//!
//! When does this ever happen?
//! Honestly, not that often in real-world systems. If you can mess with "g", chances are you can mess with something worse. Most systems pre-agree on a static DH group. But the same construction exists in Elliptic Curve Diffie-Hellman, and this becomes more relevant there.
//!

use crate::{get_g, get_p};
use num_bigint::BigUint;
use crate::ex_34_implement_a_mitm_key_fixing_attack_on_diffie_hellman_with_parameter_injection::{Message, Node};
use crate::ex_34_implement_a_mitm_key_fixing_attack_on_diffie_hellman_with_parameter_injection::Message::{EndOfProtocol, PublicKey};

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
    fn new_with_group(g: BigUint) -> Self {
        Mitm {
            node_a: Node::new(),
            node_b: Node::new_w_keys_with_group(g),
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

fn solve_with_group(g: BigUint) {
    let mut a = Node::new_w_keys();
    let mut b = Node::new();
    let mut mitm = Mitm::new_with_group(g);
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

fn solve() {
    solve_with_group(BigUint::from(1u32));
    solve_with_group(get_p());
    solve_with_group(get_p() - BigUint::from(1u32));
}

#[cfg(test)]
mod tests {
    use crate::ex_35_implement_dh_with_negotiated_groups_and_break_malicious_g_parameters::solve;

    #[test]
    #[ignore]
    fn test_solve() {
        solve();
    }
}
