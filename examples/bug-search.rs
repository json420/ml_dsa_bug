// Minimal demonstration of a valid signature that wont round-trip through encode/decode.

use blake3::{hash, Hash};
use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{KeyGen, MlDsa65, Signature, B32};

const COUNT: usize = 10_000_000;
static MESSAGE: &[u8] = b"There seems to be a round tripping issue somewhere in here";

fn main() {
    let mut seed = Hash::from_bytes([77; 32]);
    for i in 0..COUNT {
        seed = hash(seed.as_bytes());
        let mut hack = B32::default();
        hack.0.copy_from_slice(seed.as_bytes());
        let kp = MlDsa65::key_gen_internal(&hack);
        let sig = kp.signing_key().sign(MESSAGE);
        let sig_enc = sig.encode();
        if Signature::<MlDsa65>::decode(&sig_enc).is_none() {
            println!("FAIL! {} {}", seed, i);
            break;
        }
        if i % 10_000 == 0 {
            println!("{} {}", seed, i);
        }
    }
}
