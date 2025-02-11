use blake3::{hash, Hash};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, KeyGen, KeyPair, MlDsa65, Signature, VerifyingKey, B32,
};
use signature::{Signer, Verifier, Keypair};

#[cfg(test)]
mod tests {
    use super::*;

    static MESSAGE: &[u8] = b"There seems to be a round tripping issue somewhere in here";
    static GOOD: &str = "155f27eac999045cd27dc51dd07a7787fc3655493710ebfc0e45767aa3ae86de";
    static BAD: &str = "c5b99f3bd8e9d028f404b6496df4cd717437ce91d6cdf78229715d0e8cc2bfe8";

    fn gen_keypair(seed: &Hash) -> KeyPair<MlDsa65> {
        let mut hack = B32::default();
        hack.0.copy_from_slice(seed.as_bytes()); // FIXME: How do more better?
        MlDsa65::key_gen_internal(&hack)
    }

    fn roundtrip_sig(sig: Signature<MlDsa65>) {}

    #[test]
    fn it_works_not_finder() {
        let mut seed = Hash::from_bytes([69; 32]);
        for i in 0..420 {
            seed = hash(seed.as_bytes());
            let kp = gen_keypair(&seed);
            let sig = kp.signing_key().sign(MESSAGE);
            assert!(kp.verifying_key().verify(MESSAGE, &sig).is_ok());
            if i == 39 {
                assert_eq!(
                    hash(kp.signing_key().encode().as_slice()),
                    Hash::from_hex(
                        "dfeb0ddc4a2d932777f73c71e62ef03bdc4a9bc343f6cb3d212671d72aeec81d"
                    )
                    .unwrap()
                );
                assert_eq!(
                    hash(kp.verifying_key().encode().as_slice()),
                    Hash::from_hex(
                        "f0945e7a6b0c66a91078a2d5d2ed5b56872be70a5eec779dd14c396a239c0be2"
                    )
                    .unwrap()
                );
                assert_eq!(
                    hash(sig.encode().as_slice()),
                    Hash::from_hex(
                        "6bd4649f05caf55b75ac083c5182e609d8018ce6022e210c7f0cf0f22fdb557b"
                    )
                    .unwrap()
                );
            }

            let mut pub_buf = [0; 1952];
            pub_buf.copy_from_slice(kp.verifying_key().encode().as_slice());
            let mut sig_buf = [0; 3309];
            sig_buf.copy_from_slice(sig.encode().as_slice());
            println!("{} {}", i, seed);
            let pub_enc = EncodedVerifyingKey::<MlDsa65>::try_from(&pub_buf[..]).unwrap();
            let pub_key = VerifyingKey::<MlDsa65>::decode(&pub_enc);
            let sig_enc = EncodedSignature::<MlDsa65>::try_from(&sig_buf[..]).unwrap();

            // This will fail at i=39,
            // seed=c5b99f3bd8e9d028f404b6496df4cd717437ce91d6cdf78229715d0e8cc2bfe8
            let sig = Signature::<MlDsa65>::decode(&sig_enc).unwrap();
        }
    }

    #[test]
    fn it_works_not() {
        let seed = Hash::from_hex(BAD).unwrap();
        let kp = gen_keypair(&seed);
        let sig = kp.signing_key().sign(MESSAGE);
        let mut sig_buf = [0; 3309];
        sig_buf.copy_from_slice(sig.encode().as_slice());
        let sig_enc = EncodedSignature::<MlDsa65>::try_from(&sig_buf[..]).unwrap();
        let sig = Signature::<MlDsa65>::decode(&sig_enc).unwrap();
    }

    #[test]
    fn it_works() {
        let seed = Hash::from_hex(GOOD).unwrap();
        let kp = gen_keypair(&seed);
        let sig = kp.signing_key().sign(MESSAGE);
        let mut sig_buf = [0; 3309];
        sig_buf.copy_from_slice(sig.encode().as_slice());
        let sig_enc = EncodedSignature::<MlDsa65>::try_from(&sig_buf[..]).unwrap();
        let sig = Signature::<MlDsa65>::decode(&sig_enc).unwrap();
    }
}
