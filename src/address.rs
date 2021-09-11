use crate:: {
    key::PubKey,
    Ripemd160, Sha256, Digest, bs58
};
use std::fmt;

pub struct Address;

impl Address {
    /**
        Creates a wallet address from a public key. 
        * BASE58 CHECK ENCODING UNIMPLEMENTED    
    */
    pub fn from_pub_key(pk: &PubKey) -> String {
        let mut sha_hasher: Sha256 = Sha256::new();
        sha_hasher.update(&pk.as_bytes());
        let sha_hash_result = sha_hasher.finalize();

        let mut ripe_hasher: Ripemd160 = Ripemd160::new();
        ripe_hasher.update(sha_hash_result);
        let ripe_hash_result = ripe_hasher.finalize();

        //Base58 encode without identifying prefix or check sum.
        let unchecked: String = bs58::encode(ripe_hash_result).into_string();
        unchecked

        //Todo:
        //Figure out if the Base58Check Encoded address is the encode of the ripe hash byte array or the ripe hash hex string
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}