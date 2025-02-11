use blake3::{hash, Hash};
use ml_dsa::{KeyGen, MlDsa65, B32};
use signature::{Signer, Verifier};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works_not() {
        let msg = b"There seems to be a round tripping issues somewhere in here";
        let mut seed = Hash::from_bytes([69; 32]);
        for i in 0..420 {
            seed = hash(seed.as_bytes());
            let mut hack = B32::default();
            hack.0.copy_from_slice(seed.as_bytes()); // FIXME: How do more better?
            let kp = MlDsa65::key_gen_internal(&hack);
            let sig = kp.signing_key.sign(msg);
            assert!(kp.verifying_key.verify(msg, &sig).is_ok());
            if i == 41 {
                assert_eq!(
                    hash(kp.verifying_key.encode().as_slice()),
                    Hash::from_hex(
                        "f006583eeaa8820eb9184a72324ca5259251ae915c5655cda5afb9dcd9982dc0"
                    )
                    .unwrap()
                );
                assert_eq!(
                    hash(sig.encode().as_slice()),
                    Hash::from_hex(
                        "2712efcd96e43f61834a9739cc7bef851800d40a6d4bbcca96a4c10822c2faae"
                    )
                    .unwrap()
                );
            }
        }
    }
}
