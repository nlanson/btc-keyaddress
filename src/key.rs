use crate::{
    Secp256k1,
    PublicKey,
    SecretKey,
    OsRng
};
use std::fmt;

pub struct PrivKey(SecretKey);

impl PrivKey {
    
    /*
        Generates an random number of entropic source using OsRng and uses it to create a secret key in the form of a u8 array.
    */
    pub fn new_rand() -> Self {
        let mut rng = OsRng::new().expect("OsRng");
        Self(SecretKey::new(&mut rng))
    }
}

pub struct PubKey(pub PublicKey);

impl PubKey {
    
    /*
        Finds the compressed public key from a secret key.
        Is the result of static point G on the secp256k1 curve multipled k times, where k is the private key.
    */
    pub fn from_priv_key(k: &PrivKey) -> Self {
        Self(PublicKey::from_secret_key(&Secp256k1::new(),&k.0))
    }

    /*
        Extracts the uncompressed public key given the compressed (x-coord + prefix) public key.
    */
    pub fn decompress(&self) {
        let bytes_array: [u8; 65] = self.0.serialize_uncompressed();
        unimplemented!();
        //Need to check if a hashed values are the same for a byte array, hex string and PubKey struct
    }
}

impl fmt::Display for PrivKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}