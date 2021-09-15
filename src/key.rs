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
        Does not include the decompression byte.
    */
    pub fn serialize(&self) -> [u8; 32] {
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
        //(65 byte size = 64byte key + 1 byte uncompressed identifier)
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

#[cfg(test)]
mod tests {
    use super::{
        PrivKey, PubKey,
        decode_02x
    };

    //The private key to use in tests
    const TEST_PRIV_KEY_HEX: &str = "55aadc357c5a94ce6eb7cec820b7ee1e8216ca9f6fff9e291ab7c34cb27f2ccb";
    const TEST_PUB_KEY_HEX: &str = "0204664c60ceabd82967055ccbd0f56a1585dfbd42032656efa501c463b16fbdfe";

    //Test priv key from hex string to PrivKey Struct
    fn test_priv_key() -> PrivKey {
        PrivKey::from_slice(&decode_02x(TEST_PRIV_KEY_HEX))
    }

    #[test]
    fn private_key_tests() {
        let test_key: PrivKey = test_priv_key();
        let expected_public_key = PubKey::from_slice(&decode_02x(TEST_PUB_KEY_HEX));
        let expected_compressed_wif = "Kz6Ei3hbi461rDN292f2funoueKegmYAn6UKppEktYAgBhUu65Q7".to_string();
        let expected_uncompressed_wif = "5JU1qir5EqH6BF8Uu7ihFhxh5gGZ6qcA1hfN2mgpZ4taoTTWjzu".to_string();

        let derived_public_key = PubKey::from_priv_key(&test_key);
        let derived_compressed_wif = test_key.export_as_wif(true);
        let derived_uncompressed_wif = test_key.export_as_wif(false);
        

        //Is the derived public key the same as the expected public key?
        assert_eq!(derived_public_key.as_hex(), TEST_PUB_KEY_HEX);

        //Is the decompressed derived key the same as the decompressed expected key?
        assert_eq!(expected_public_key.decompressed_bytes(), derived_public_key.decompressed_bytes());

        //Are the encoded WIFs the same?
        assert_eq!(expected_compressed_wif, derived_compressed_wif);
        assert_eq!(expected_uncompressed_wif, derived_uncompressed_wif);
    }

    #[test]
    fn public_key_tests() {
        let test_key: PubKey = PubKey::from_slice(&decode_02x(TEST_PUB_KEY_HEX));
        let expected_compression_prefix = 0x02;
        let expected_uncompressed_prefix = 0x04;

        let derived_compression_prefix = test_key.as_bytes()[0];
        let derived_uncompressed_prefix = test_key.decompressed_bytes()[0];

        //Are the expected prefixes the same for derived uncompressed and compressed test keys.
        assert_eq!(expected_compression_prefix, derived_compression_prefix);
        assert_eq!(expected_uncompressed_prefix, derived_uncompressed_prefix);
    }

    #[test]
    fn random_public_key_tests() {
        let k: PrivKey = PrivKey::new_rand();
        let test_key: PubKey = PubKey::from_priv_key(&k);

        //Is the first byte of the compressed key the compression prefix?
        assert!(
            match test_key.as_bytes()[0] {
            0x02 => true,
            0x03 => true,
            _ => false
            }
        );

        //Is the first byte of the uncompressed key the uncompressed indicator?
        assert!(
            match test_key.decompressed_bytes()[0] {
                0x04 => true,
                _ => false
            }
        );
    }
}