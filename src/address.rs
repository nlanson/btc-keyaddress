use crate:: {
    key::PubKey,
    hash,
    bs58check,
    util::try_into
};
use std::fmt;

pub struct Address;

impl Address {
    /**
        Creates a wallet address from a public key. (compressed)
        * Base58Check( Riped160( Sha256( Public Key ) ) )
    */
    pub fn from_pub_key(pk: &PubKey, compressed: bool) -> String {
        let mut pubkey_bytes: Vec<u8> = pk.as_bytes().to_vec();
        if !compressed { pubkey_bytes = pk.decompressed_bytes().to_vec(); }
        
        let mut hash: Vec<u8> = hash::sha256(&pubkey_bytes).to_vec(); //Initialise variable hash as mutable Vec<u8> and assign the sha256 hash of the public key.
        hash = hash::ripemd160(hash).to_vec(); //hash now equals the ripemd160 hash of itself. Ripemd160(Sha256(PublicKey))
        bs58check::check_encode(bs58check::VersionPrefix::BTCAddress, hash) //Return the Bas58Check Encoded string of the hash
    }

    /**
        Verifies that an address is valid by checking the payload and checksum
    */
    pub fn is_valid(address: String) -> bool {
        let decoded: Vec<u8> = bs58check::decode(address).expect("Failed to decode provided address");
        if decoded.len() != 25 { return false }

        let checksum: [u8; 4] = try_into( //Extract the checksum from the decoded address
            decoded[decoded.len()-4..decoded.len()].to_vec()
        ); 
        let payload_hash: [u8; 4] = try_into( //Hash the payload of the address
            hash::sha256(hash::sha256(
            decoded[0..decoded.len()-4].to_vec()
            ))[0..4].to_vec()
        );

        //Compare the attached checksum to the hashed payload
        if checksum == payload_hash {
            return true
        }

        false
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}