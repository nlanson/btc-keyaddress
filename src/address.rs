use crate:: {
    key::PubKey,
    hash,
    bs58
};
use std::fmt;

pub struct Address;

impl Address {
    /**
        Creates a wallet address from a public key. (compressed)
    */
    pub fn from_pub_key(pk: &PubKey) -> String {
        //Initialise variable hash as mutable Vec<u8> and assign the sha256 hash of the public key.
        let mut hash: Vec<u8> = hash::sha256(&pk.as_bytes());
        hash = hash::ripemd160(hash); //hash now equals the ripemd160 hash of itself. Ripemd160(Sha256(PublicKey))
        hash.splice(0..0, [0 as u8]); //Prepend prefix 0 to identify as regular wallet
        let checksum: Vec<u8> = hash::sha256(hash::sha256(&hash))[0..4].to_vec(); //Initialise variable checksum as the first 4 bytes of the double sha256 hash of the prepended hash160.
        hash.splice(hash.len()..hash.len(), checksum); //Append the checksum to the hash160.
        
        bs58::encode(hash).into_string() //Return the base58 encoded hash with prefix and suffix. This is Base58Check
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}