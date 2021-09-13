use crate::{
    Secp256k1,
    PublicKey,
    SecretKey,
    SecpOsRng,
    bs58check,
    util::decode_02x,
    util::encode_02x,
    util::try_into
};
use std::fmt;
use bitcoin_hashes::hex::ToHex;

pub struct PrivKey(SecretKey);

impl PrivKey {
    
    /**
        Generates an random number of entropic source using OsRng and uses it to create a secret key in the form of a u8 array.
    */
    pub fn new_rand() -> Self {
        let mut rng = SecpOsRng::new().expect("OsRng");
        Self(SecretKey::new(&mut rng))
    }

    /**
        Use a predefined byte array as a secret key.
    */
    pub fn from_slice(byte_array: &[u8]) -> Self {
        Self(SecretKey::from_slice(byte_array).expect("Invalid slice"))
    }


    /**
        Serializes the private key into a array of bytes.
    */
    fn serialize(&self) -> [u8; 32] {
        let hex = self.0.to_hex();
        try_into(decode_02x(&hex[..]))
    }

    /*
        Export the private key a wallet-import-format (Base58Check Encoded with prefix)
        * Use the parameter to indicate if WIF should include the compression byte.
    */
    pub fn export_as_wif(&self, compressed: bool) -> String {
        let mut key: Vec<u8> = self.serialize().to_vec();
        if compressed {
            key.append(&mut vec![0x01]);
        }
        
        bs58check::check_encode(bs58check::VersionPrefix::PrivateKeyWIF, &key)
    }
}

pub struct PubKey(PublicKey);

impl PubKey {
    
    /**
        Finds the compressed public key from a secret key.

        Is the result of static point G on the secp256k1 curve multipled k times, where k is the private key.
    */
    pub fn from_priv_key(k: &PrivKey) -> Self {
        Self(PublicKey::from_secret_key(&Secp256k1::new(),&k.0))
    }

    /**
        Use a predefined byte array as a public key.
        
        Make sure you know the private key!
    */
    pub fn from_slice(byte_array: &[u8]) -> Self {
        Self(PublicKey::from_slice(byte_array).expect("Invalid slice"))
    }

    /**
        Returns the compressed public key as a byte array.
    */
    pub fn as_bytes(&self) -> [u8; 33] {
        //Len should be 33 (32bytes + sign identifier)
        self.0.serialize()
    }

    /**
        Extracts the uncompressed public key given the compressed (x-coord + prefix) public key.

        Returns a byte aray.
    */
    pub fn decompressed_bytes(&self) -> [u8; 65] {
        //(65 byte size = 64byte key + 1 byte uncompressed identofier)
        self.0.serialize_uncompressed()
    }

    /**
       Return the compressed public key as a hex string.
    */
    pub fn as_hex(&self) -> String {
        encode_02x(&self.as_bytes())
    }

    /**
       Returns the uncompressed  public key as a hex string.
    */
    pub fn decompressed_hex(&self) -> String {
        encode_02x(&self.decompressed_bytes())
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