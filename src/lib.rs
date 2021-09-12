/*
    Wrapper around the rust-secp256k1 library to 
    create random private keys, public keys and
    addresses in both compressed and uncompressed
    format.

    Not for use with the bitcoin main network.

    Based on chapter 4 of the bitcoin book. (https://github.com/bitcoinbook/bitcoinbook/)
*/

pub mod key;
pub mod address;
pub mod hash;

pub use secp256k1::rand::rngs::OsRng;
pub use secp256k1::{PublicKey, Secp256k1, SecretKey};
pub use sha2::{Sha256, Digest};
pub use ripemd160::Ripemd160;
pub use bs58;


/**
    Tests aren't implemented yet.
*/
#[cfg(test)]
mod tests {
    use sha2::{Sha256, Digest};
    use crate::{
        key::PubKey,
        key::PrivKey,
        address::Address
    };

    //This test was written to check if a uncompressed public key in form [u8; 65] can be hashed
    //similarly to a compressed public key in form string. 
    #[test]
    fn hash_identical_test() {
        let k: PrivKey = PrivKey::new_rand();
        let pk: PubKey = PubKey::from_priv_key(&k);

        //Hash of public key as bytes array
        let mut hasher1 = Sha256::new();
        hasher1.update(pk.as_bytes());
        let result1 = hasher1.finalize();

        //Hash of public key as bytes array
        let mut hasher2 = Sha256::new();
        hasher2.update(pk.as_hex());
        let result2 = hasher2.finalize();

        //Hashing the byte array and hashing the hex string is not identical in this case.
        assert_eq!(result1, result2);
    }

    //Test doesn't work yet.
    #[test]
    fn test_hash160_from_pubkey() {
        let k: PrivKey = PrivKey::new_rand();
        let pk: PubKey = PubKey::from_priv_key(&k);
        let hash160: String = Address::from_pub_key(&pk);

        assert!(1==1);
    }
}
