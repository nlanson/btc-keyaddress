use crate:: {
    key::PubKey,
    hash,
    bs58check
};
use std::fmt;

pub struct Address;

impl Address {
    /**
        Creates a wallet address from a public key. (compressed)
        * Base58Check( Riped160( Sha256( Public Key ) ) )
    */
    pub fn from_pub_key(pk: &PubKey, compressed: bool) -> String {
        let mut pubkey_bytes = pk.as_bytes();
        if !compressed { pubkey_bytes = pk.decompressed_bytes(); }
        
        let mut hash: Vec<u8> = hash::sha256(&pubkey_bytes); //Initialise variable hash as mutable Vec<u8> and assign the sha256 hash of the public key.
        hash = hash::ripemd160(hash); //hash now equals the ripemd160 hash of itself. Ripemd160(Sha256(PublicKey))
        bs58check::check_encode(bs58check::VersionPrefix::BTCAddress, hash) //Return the Bas58Check Encoded string of the hash
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}