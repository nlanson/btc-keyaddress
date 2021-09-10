/*
    Wrapper around the rust-secp256k1 library to 
    create random private keys, public keys and
    addresses in both compressed and uncompressed
    format.

    Not for use with the bitcoin main network.

    Based on chapter 4 of the bitcoin book. (https://github.com/bitcoinbook/bitcoinbook/)
*/

use secp256k1::rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use bs58;
use bitcoin_hashes::{sha256, ripemd160};

/*
    Generates an random number of entropic source using OsRng and uses it to create a secret key in the form of a u8 array.
*/
pub fn new_random_priv_key() -> SecretKey {
    let mut rng = OsRng::new().expect("OsRng");
    SecretKey::new(&mut rng)
}

/*
    Finds the public key from a secret key.
    Is the result of static point G on the secp256k1 curve multipled k times, where k is the private key.
*/
pub fn pub_key_from_priv_key(k: &SecretKey) -> PublicKey {
    PublicKey::from_secret_key(&Secp256k1::new(),k)
}

#[cfg(test)]
mod tests {
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    use crate::new_random_priv_key;
    
    #[test]
    fn keys_test() {
        let secp = Secp256k1::new();
        let k: SecretKey = new_random_priv_key();
        let pk: PublicKey = PublicKey::from_secret_key(&secp, &k);

        assert_eq!(pk, PublicKey::from_secret_key(&secp, &k));
    }
}
