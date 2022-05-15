/*

ECB cut-and-paste

Write a k=v parsing routine, as if for a structured cookie. The routine should take:

foo=bar&baz=qux&zap=zazzle

... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}

(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address. You should have something like:

profile_for("foo@bar.com")

... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}

... encoded as:

email=foo@bar.com&uid=10&role=user

Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

    Encrypt the encoded user profile under the key; "provide" that to the "attacker".
    Decrypt the encoded user profile and parse it.

Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.

----
## Solution
1. Find block size.
2. use `admin` + padding to fill the whole block as input. The first block is what I need.
2. create email long enough to push "user" to last block.
3. replace last block with the one produce at step 2.
4. return result

 */

use crypto::aes::ecb::find_block_size;
use crypto::Pkcs7;

const TARGET_ROLE: &str = "admin";

pub struct Profile {
    email: String,
    user_id: String,
    role: String,
}
impl Profile {
    fn new(email: String, user_id: String, role: String) -> Self {
        Self {
            email,
            user_id,
            role,
        }
    }
    fn encode(&self) -> String {
        format!(
            "email={}&uid={}&role={}",
            self.email, self.user_id, self.role
        )
    }
    fn decode(s: String) -> Self {
        s.into()
    }
    fn decrypt(key: [u8; 16], encrypted: &[u8]) -> Self {
        String::from_utf8(Pkcs7::remove_padding_unchecked(crypto::aes::ecb::decrypt(
            &key, encrypted,
        )))
        .unwrap()
        .into()
    }
    fn encrypt(&self, key: [u8; 16]) -> Vec<u8> {
        let encoded = self.encode();
        let padded = Pkcs7::pad(encoded.as_bytes(), 16);
        crypto::aes::ecb::encrypt(&key, &padded)
    }
}
impl From<String> for Profile {
    fn from(encoded: String) -> Self {
        println!("Encoded: {}", encoded);
        let mut parts = encoded.split("&");
        let get_value = |p: Option<&str>| {
            let p = p.unwrap();
            let mut parts = p.split("=");
            parts.next();
            parts.next().take().map(|v| v.to_string()).unwrap()
        };
        let email = get_value(parts.next());
        let user_id = get_value(parts.next());
        let role = get_value(parts.next());
        Profile::new(email, user_id, role)
    }
}
fn profile_for(email: &str) -> Profile {
    Profile::new(
        email.replace("&", "").replace("=", ""),
        "10".to_string(),
        "user".to_string(),
    )
}

fn solve(key: &[u8; 16], oracle: impl Fn(Vec<u8>) -> Vec<u8> + Clone) -> Vec<u8> {
    let block_len = find_block_size(oracle.clone()).unwrap();

    let gen_padding = |x| (0..x).map(|_| 'a').collect::<String>();

    let padding_admin_padding = format!(
        "{}{}",
        gen_padding(block_len - "email=".len()),
        String::from_utf8_lossy(&Pkcs7::pad(b"admin", block_len))
    );

    // Format: [email=____, admin____, &uid=10&role=user]
    // admin gets its own block.
    let mut admin_encrypted_block =
        Vec::from(&oracle(padding_admin_padding.as_bytes().to_vec()).as_slice()[16..32]);
    // admin_encrypted_block contains "admin____"
    // Last step is use an email long enough to push `user` of `role=user` in its own block:
    // email=foo@bar.it&uid=10role=]user
    let fixed = "email=&uid=10&role=user";

    // I'll need at least this amount of blocks for my encrypted profile:
    let total_blocks_len = (fixed.len() as f64 / block_len as f64).ceil() as usize;
    let total_blocks_bytes_len = total_blocks_len * block_len;

    let profile_email = format!(
        "f{}@bar.foo",
        gen_padding(total_blocks_bytes_len - fixed.len() - TARGET_ROLE.len())
    );
    println!(
        "Block len: {}, profile email: '{}'",
        block_len, profile_email
    );

    let user_profile = profile_for(&profile_email).encrypt(*key);
    let mut ret = Vec::from(&user_profile.as_slice()[0..32]);
    ret.append(&mut admin_encrypted_block);
    return ret;
}

fn build_oracle(key: Vec<u8>) -> impl Fn(Vec<u8>) -> Vec<u8> + Clone {
    return move |plaintext: Vec<u8>| -> Vec<u8> {
        const KEY_SIZE: usize = 16;
        let mut k = [0; KEY_SIZE];
        k.copy_from_slice(&key.as_slice()[..KEY_SIZE]);
        profile_for(&String::from_utf8_lossy(&plaintext)).encrypt(k)
    };
}

#[cfg(test)]
mod test {
    use super::Profile;
    use crate::ex_13_ecb_cut_and_paste::{build_oracle, solve, TARGET_ROLE};
    use crypto::aes::random_key;

    #[test]
    fn test_profile_encoder() {
        let encoded = "email=foo@bar.com&uid=10&role=user".to_string();
        assert_eq!(encoded.clone(), Profile::from(encoded).encode());
    }
    #[test]
    fn test_solve() {
        let key = random_key();
        let oracle = build_oracle(key.to_vec());
        let forged = solve(&key, oracle);
        assert_eq!(Profile::decrypt(key, &forged).role, TARGET_ROLE);
    }
}
