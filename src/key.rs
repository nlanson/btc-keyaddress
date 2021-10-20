use std::str::FromStr;

use crate::{
    Secp256k1,
    PublicKey,
    SecretKey,
    SecpOsRng,
    encoding::{
        bs58check as bs58check
    },
    util::decode_02x,
    util::try_into,
    util::Network,
    hash
};

/**
    Enum to handle errors in the key module.
*/
#[derive(Debug)]
pub enum KeyError {
    BadSlice(),
    BadArithmatic(),
    BadWif(),
    BadString()
}

/**
    Define methods shared by Public and Private keys.
*/
pub trait Key {
    /**
        Create a new instance of Self from a u8 slice.
    */
    fn from_slice(byte_array: &[u8]) -> Result<Self, KeyError>
    where Self: Sized;

    /**
        Return self as a byte array.
    */
    fn as_bytes<const N: usize>(&self) -> [u8; N];
}



/*
    Define the tuple structs PrivKey and PubKey.

    The structs are essentially a wrapper for SecretKey and PublicKey
    structs in the Secp256k1 lirabry.
*/
#[derive(Debug, Clone, Copy)]
pub struct PrivKey(SecretKey);
#[derive(Debug, Clone, Copy)]
pub struct PubKey(PublicKey);

impl PrivKey {
    
    /**
        Generates an random number of entropic source using OsRng and uses it to create a secret key in the form of a u8 array.
    */
    pub fn new_rand() -> Self {
        let mut rng = SecpOsRng::new().expect("OsRng");
        Self(SecretKey::new(&mut rng))
    }

    /*
        Export the private key a wallet-import-format (Base58Check Encoded with prefix)
        * Use the parameter to indicate if WIF should include the compression byte.
    */
    pub fn export_as_wif(&self, compressed: bool, network: Network) -> String {
        let mut key: Vec<u8> = self.as_bytes::<32>().to_vec();
        if compressed {
            key.append(&mut vec![0x01]);
        }
        
        match network {
            Network::Bitcoin => bs58check::check_encode(bs58check::VersionPrefix::PrivateKeyWIF, &key),
            Network::Testnet => bs58check::check_encode(bs58check::VersionPrefix::TestNetPrivateKeyWIF, &key)
        }
        
    }

    /**
        Takes in self and another slice and returns the sum of the values modulo
        by the order of the SECP256K1 curve.
    */
    pub fn add_assign(&mut self, other: &[u8]) -> Result<(), KeyError> {
        match self.0.add_assign(other) {
            Ok(_) => Ok(()),
            Err(_) => Err(KeyError::BadArithmatic())
        }
    }

    pub fn raw(&self) -> SecretKey {
        self.0
    }

    /**
      Create a private key from wif
    */
    pub fn from_wif(wif: &str) -> Result<Self, KeyError> {
        let mut bytes = match bs58check::decode(&wif.to_string()) {
            Ok(x) => x,
            Err(_) => return Err(KeyError::BadWif())
        };

        bytes.remove(0); //remove the version prefix
        bytes.splice(bytes.len()-4..bytes.len(), vec![]); //remove the checksum
        if bytes.len() == 33 {
            bytes.remove(bytes.len()-1); //remove the compression byte
            return Ok(Self::from_slice(&bytes)?);
        } else if bytes.len() == 32 {
            return Ok(Self::from_slice(&bytes)?)
        }
        
        return Err(KeyError::BadWif())
        
    }

    pub fn get_pub(&self) -> PubKey {
        PubKey::from_priv_key(self)
    }
}

impl Key for PrivKey {
    fn from_slice(byte_array: &[u8]) -> Result<Self, KeyError> {
        match SecretKey::from_slice(byte_array) {
            Ok(x) => Ok(Self(x)),
            _ => Err(KeyError::BadSlice())
        }
    }


    /**
        32 bytes
    */
    fn as_bytes<const N: usize>(&self) -> [u8; N] {
        let hex = self.0.to_string();
        try_into(decode_02x(&hex[..]))
    }
}

impl PubKey {
    
    /**
        Finds the compressed public key from a secret key.

        Is the result of static point G on the secp256k1 curve multipled k times, where k is the private key.
    */
    pub fn from_priv_key(k: &PrivKey) -> Self {
        Self(PublicKey::from_secret_key(&Secp256k1::new(),&k.0))
    }


    /**
        Extracts the uncompressed public key given the compressed (x-coord + prefix) public key.

        Returns a byte aray.
    */
    pub fn decompressed_bytes(&self) -> [u8; 65] {
        //(65 byte size = 64byte key + 1 byte uncompressed identifier)
        self.0.serialize_uncompressed()
    }

    pub fn add_assign(&mut self, other: &[u8]) -> Result<(), KeyError> {
        match self.0.add_exp_assign(&Secp256k1::new(), other) {
            Ok(_) => Ok(()),
            Err(_) => Err(KeyError::BadArithmatic())
        }
    }

    pub fn raw(&self) -> PublicKey {
        self.0
    }

    /**
        Returns the Hash160 of the compressed public key
    */
    pub fn hash160(&self) -> Vec<u8> {
        hash::hash160(self.as_bytes::<33>()).to_vec()
    }

    pub fn hex(&self) -> String {
        self.0.to_string()
    }

    pub fn from_str(hex: &str) -> Result<Self, KeyError> {
        let pk = match PublicKey::from_str(hex) {
            Ok(x) => x,
            Err(_) => return Err(KeyError::BadString())
        };

        Ok( Self( pk ) )
    }
}

impl Key for PubKey {
    fn from_slice(byte_array: &[u8]) -> Result<Self, KeyError> {
        match PublicKey::from_slice(byte_array) {
            Ok(x) => Ok(Self(x)),
            _ => Err(KeyError::BadSlice())
        }
    }

    /**
        33 bytes
    */
    fn as_bytes<const N: usize>(&self) -> [u8; N] {
        try_into(self.0.serialize()[0..N].to_vec())
    }
}

impl Eq for PubKey { }
impl PartialEq for PubKey { 
    //Check the key bytes are equal
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes::<33>()
    }
}

impl PartialOrd for PubKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PubKey {
    //Sort lexicographically
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.hex().cmp(&other.hex())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PrivKey, PubKey, Key,
        decode_02x,
        Network
    };
    use crate::{
        util::encode_02x
    };

    //The private key to use in tests
    const TEST_PRIV_KEY_HEX: &str = "55aadc357c5a94ce6eb7cec820b7ee1e8216ca9f6fff9e291ab7c34cb27f2ccb";
    const TEST_PUB_KEY_HEX: &str = "0204664c60ceabd82967055ccbd0f56a1585dfbd42032656efa501c463b16fbdfe";

    //Test priv key from hex string to PrivKey Struct
    fn test_priv_key() -> PrivKey {
        PrivKey::from_slice(&decode_02x(TEST_PRIV_KEY_HEX)).unwrap()
    }

    #[test]
    fn private_key_tests() {
        let test_key: PrivKey = test_priv_key();
        let expected_public_key = PubKey::from_slice(&decode_02x(TEST_PUB_KEY_HEX)).unwrap();
        let expected_compressed_wif = "Kz6Ei3hbi461rDN292f2funoueKegmYAn6UKppEktYAgBhUu65Q7".to_string();
        let expected_uncompressed_wif = "5JU1qir5EqH6BF8Uu7ihFhxh5gGZ6qcA1hfN2mgpZ4taoTTWjzu".to_string();

        let derived_public_key = PubKey::from_priv_key(&test_key);
        let derived_compressed_wif = test_key.export_as_wif(true, Network::Bitcoin);
        let derived_uncompressed_wif = test_key.export_as_wif(false, Network::Bitcoin);
        

        //Is the derived public key the same as the expected public key?
        assert_eq!(encode_02x(&derived_public_key.as_bytes::<33>()), TEST_PUB_KEY_HEX);

        //Is the decompressed derived key the same as the decompressed expected key?
        assert_eq!(expected_public_key.decompressed_bytes(), derived_public_key.decompressed_bytes());

        //Are the encoded WIFs the same?
        assert_eq!(expected_compressed_wif, derived_compressed_wif);
        assert_eq!(expected_uncompressed_wif, derived_uncompressed_wif);
    }

    #[test]
    fn public_key_tests() {
        let test_key: PubKey = PubKey::from_slice(&decode_02x(TEST_PUB_KEY_HEX)).unwrap();
        let expected_compression_prefix = 0x02;
        let expected_uncompressed_prefix = 0x04;

        let derived_compression_prefix = test_key.as_bytes::<33>()[0];
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
            match test_key.as_bytes::<33>()[0] {
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

    #[test]
    fn privkey_from_wif() {
        let testnet_wifs: Vec<&str> = vec![
            "cRQbJ2t9mfrAXE9THANTGnj42ysgKtxMaTv9rw9eRMrZBfNAsPv9",
            "92TBwcKPNuJUz9R7rt4W4aUCZczhdTGiNBBELUDqMUP6w7V3tPN"
        ];

        let expected_pk: PrivKey = PrivKey::from_slice(&[114, 38, 26, 249, 94, 159, 251, 207, 115, 108, 169, 140, 97, 249, 149, 161, 110, 42, 120, 163, 193, 164, 192, 248, 91, 30, 123, 98, 59, 24, 220, 54]).unwrap();
        
        for i in 0..testnet_wifs.len() {
            assert!(PrivKey::from_wif(testnet_wifs[i]).unwrap().as_bytes() == expected_pk.as_bytes::<32>());
        }

        let mainnet_wifs: Vec<&str> = vec![
            "cTgPUEMicCdp7afFt7436LwduW8o3oiYVQyJMoiVscGDaLDQZGYr",
            "92y3prhVTZ6AmYBw83jNmiDqEi3DhWchDL2Rn3RosSD4JbZ3jZu"
        ];

        let expected_pk: PrivKey = PrivKey::from_slice(&[181, 243, 36, 71, 85, 202, 145, 148, 138, 199, 106, 36, 223, 13, 86, 51, 15, 97, 88, 163, 177, 89, 167, 155, 157, 230, 44, 107, 160, 171, 46, 60]).unwrap();
        
        for i in 0..mainnet_wifs.len() {
            assert!(PrivKey::from_wif(mainnet_wifs[i]).unwrap().as_bytes() == expected_pk.as_bytes::<32>());
        }
    }
}