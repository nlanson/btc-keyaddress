/*
    Wrapper around the rust-secp256k1 library to 
    create random private keys, public keys and
    addresses in both compressed and uncompressed
    format.

    Not for use with the bitcoin main network.

    Based on chapter 4 of the bitcoin book. (https://github.com/bitcoinbook/bitcoinbook/)
*/

pub mod key;

pub use secp256k1::rand::rngs::OsRng;
pub use secp256k1::{PublicKey, Secp256k1, SecretKey};
pub use bs58;
pub use bitcoin_hashes::{sha256, ripemd160};


#[cfg(test)]
mod tests {
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    use crate::key::{
        PrivKey, PubKey
    };
    
    #[test]
    fn keys_test() {
        let secp = Secp256k1::new();
        let k: PrivKey = PrivKey::new_rand();
        let pk: PubKey = PubKey::from_priv_key(&k);

        assert_eq!(pk.0, PubKey::from_priv_key(&k).0);
    }
}
