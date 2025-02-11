// Minimal demonstration of a valid signature that wont round-trip through encode/decode.

use ml_dsa::{EncodedSignature, KeyGen, MlDsa65, Signature, B32};
use signature::Signer;

static SEED: [u8; 32] = [
    197, 185, 159, 59, 216, 233, 208, 40, 244, 4, 182, 73, 109, 244, 205, 113, 116, 55, 206, 145,
    214, 205, 247, 130, 41, 113, 93, 14, 140, 194, 191, 232,
];
static MESSAGE: &[u8] = b"There seems to be a round tripping issue somewhere in here";

fn main() {
    let mut seed = B32::default();
    seed.0.copy_from_slice(&SEED);
    let kp = MlDsa65::key_gen_internal(&seed);
    let sig = kp.signing_key().sign(MESSAGE);

    let mut sig_buf = [0; 3309];
    sig_buf.copy_from_slice(sig.encode().as_slice());
    let sig_enc = EncodedSignature::<MlDsa65>::try_from(&sig_buf[..]).unwrap();
    let _sig = Signature::<MlDsa65>::decode(&sig_enc).unwrap(); // This will fail
}
