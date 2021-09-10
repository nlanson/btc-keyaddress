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
    use sha2::{Sha256, Digest}; //Temporary

    use crate::key::{
        PrivKey, PubKey
    };
    
    #[test]
    fn keys_test() {
        let k: PrivKey = PrivKey::new_rand();
        let pk: PubKey = PubKey::from_priv_key(&k);

        assert_eq!(pk.0, PubKey::from_priv_key(&k).0);
    }

    //This test was written to check if a uncompressed public key in form [u8; 65] can be hashed
    //similarly to a compressed public key in form string. 
    #[test]
    fn hash_identical_test() {
        let k: PrivKey = PrivKey::new_rand();
        let pk: PubKey = PubKey::from_priv_key(&k);
        

        //String from serialized.
        let serialised = pk.0.serialize();
        let s = serialised.iter().map(|x| format!("{:02x}", x)).collect::<String>();

        //String from mehtod
        let a = pk.0.to_string();

        //Should be equal
        assert_eq!(s, a);


        //Hash of serialised to string
        let mut hasher1 = Sha256::new();
        hasher1.update(a);
        let result1 = hasher1.finalize();
        
        //Hash of string method
        let mut hasher2 = Sha256::new();
        hasher2.update(s);
        let result2 = hasher2.finalize();

        //Should be equal
        assert_eq!(result1, result2);
    }
}
