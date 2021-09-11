use crate::{
    Secp256k1,
    PublicKey,
    SecretKey,
    OsRng
};
use std::fmt;

pub struct PrivKey(SecretKey);

impl PrivKey {
    
    /**
        Generates an random number of entropic source using OsRng and uses it to create a secret key in the form of a u8 array.
    */
    pub fn new_rand() -> Self {
        let mut rng = OsRng::new().expect("OsRng");
        Self(SecretKey::new(&mut rng))
    }

    /**
        Use a predefined byte array as a secret key.
    */
    pub fn from_slice(byte_array: &[u8]) -> Self {
        Self(SecretKey::from_slice(byte_array).expect("Invalid slice"))
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
        self.0.serialize()
    }

    /**
        Extracts the uncompressed public key given the compressed (x-coord + prefix) public key.

        Returns a byte aray.
    */
    pub fn decompressed_bytes(&self) -> [u8; 65] {
        let bytes_array: [u8; 65] = self.0.serialize_uncompressed();
        println!("{:?}", bytes_array);
        bytes_array
        //unimplemented!();
        //Need to check if a hashed values are the same for a byte array, hex string and PubKey struct
    }

    /**
       Return the compressed public key as a hex string.
    */
    pub fn as_hex(&self) -> String {
        // self.0.serialize()
        // .iter().map(|x| 
        //     format!("{:02x}", x)
        // ).collect::<String>()
        self.0.to_string()
    }

    /**
       Takes in an uncompressed public key as a byte array and returns it's hex form as a string.

       Uncompressed key can be created using the method Self::decompressed_bytes().
    */
    pub fn decompressed_hex(bytes: [u8; 65]) -> String {
        bytes.iter().map( |x| 
            format!("{:02x}", x)
        ).collect::<String>()
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