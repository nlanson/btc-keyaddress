use std::str::FromStr;
use crate::{
    Secp256k1,
    PublicKey,
    SecretKey,
    SecpOsRng,
    encoding::{
        base58::Base58,
        version_prefix::VersionPrefix
    },
    util::decode_02x,
    util::try_into,
    util::Network,
    hash,
    lib_SchnorrPublicKey,
    lib_SchnorrKeyPair,
    taproot::{
        TreeNode,
        TapTweakHash
    }
};


/// Enum to handle errors in the key module
#[derive(Debug)]
pub enum KeyError {
    BadSlice(),
    BadArithmatic(),
    BadWif(),
    BadString()
}



//ECC Keys
#[derive(Debug, Clone, Copy)]
pub struct PrivKey(SecretKey);

#[derive(Debug, Clone, Copy)]
pub struct PubKey(PublicKey);


// Schnorr Keys
#[derive(Debug, Clone, Copy)]
pub struct SchnorrPublicKey(lib_SchnorrPublicKey);

#[derive(Debug, Clone, Copy)]
pub struct SchnorrKeyPair(lib_SchnorrKeyPair);


/// Methods shared in all key structs
pub trait Key<T> {
    /// Create a new instance of self from a slice
    fn from_slice(byte_array: &[u8]) -> Result<Self, KeyError>
    where Self: Sized;

    /// Return self as a byte array
    fn as_bytes<const N: usize>(&self) -> [u8; N];

    /// Return the underlying struct
    fn raw(&self) -> T;

    /// Create self from a string
    fn from_str(string: &str) -> Result<Self, KeyError>
    where Self: Sized;
}


impl PrivKey {
    ///Generates an random number of entropic source using OsRng and uses it to create a secret key in the form of a u8 array.
    pub fn new_rand() -> Self {
        let mut rng = SecpOsRng::new().expect("OsRng");
        Self(SecretKey::new(&mut rng))
    }

    /// Returns a string representation of self. 
    /// For private keys, this is a Base58 check encoded string.
    pub fn to_string(&self, compressed: bool, network: Network) -> String {
        let mut key: Vec<u8> = self.as_bytes::<32>().to_vec();
        if compressed {
            key.append(&mut vec![0x01]);
        }
        
        match network {
            Network::Bitcoin => Base58::new(Some(VersionPrefix::PrivateKeyWIF), &key).check_encode(),
            Network::Testnet => Base58::new(Some(VersionPrefix::TestNetPrivateKeyWIF), &key).check_encode()
        }
        
    }

    /// Adds other to self modulus SECP256K1 ORDER
    pub fn add_assign(&mut self, other: &[u8]) -> Result<(), KeyError> {
        match self.0.add_assign(other) {
            Ok(_) => Ok(()),
            Err(_) => Err(KeyError::BadArithmatic())
        }
    }

    /// Get the public key of self
    pub fn get_pub(&self) -> PubKey {
        PubKey::from_priv_key(self)
    }

    /// Get the schnorr equivalent of self
    pub fn schnorr(&self) -> SchnorrKeyPair {
        SchnorrKeyPair::from_priv_key(self).unwrap()
    }
}

impl Key<SecretKey> for PrivKey {
    fn from_slice(byte_array: &[u8]) -> Result<Self, KeyError> {
        match SecretKey::from_slice(byte_array) {
            Ok(x) => Ok(Self(x)),
            _ => Err(KeyError::BadSlice())
        }
    }

    fn as_bytes<const N: usize>(&self) -> [u8; N] {
        let hex = self.0.to_string();
        try_into(decode_02x(&hex[..]))
    }

    fn raw(&self) -> SecretKey {
        self.0
    }

    /// Private key string format is WIF format (Base58)
    fn from_str(wif: &str) -> Result<Self, KeyError> {
        let mut bytes = match Base58::decode(wif) {
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
}

impl PubKey {
    
    /// Create a public key from private key
    pub fn from_priv_key(k: &PrivKey) -> Self {
        Self(PublicKey::from_secret_key(&Secp256k1::new(),&k.0))
    }


    
    /// Extracts the uncompressed public key given the compressed (x-coord + prefix) public key.
    pub fn decompressed_bytes(&self) -> [u8; 65] {
        //(65 byte size = 64byte key + 1 byte uncompressed identifier)
        self.0.serialize_uncompressed()
    }

    /// Adds other to self
    pub fn add_assign(&mut self, other: &[u8]) -> Result<(), KeyError> {
        match self.0.add_exp_assign(&Secp256k1::new(), other) {
            Ok(_) => Ok(()),
            Err(_) => Err(KeyError::BadArithmatic())
        }
    }

    ///Returns the Hash160 of the compressed public key
    pub fn hash160(&self) -> Vec<u8> {
        hash::hash160(self.as_bytes::<33>()).to_vec()
    }

    /// Return a hexadecimal string representation of self
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }

    /// Convert self to a schnorr key by removing the oddity byte
    pub fn schnorr(&self) -> SchnorrPublicKey {
        let mut data = self.as_bytes::<33>().to_vec();
        data.remove(0); //Remove the oddity byte

        SchnorrPublicKey::from_slice(&data).unwrap()
    }
}

impl Key<PublicKey> for PubKey {
    fn from_slice(byte_array: &[u8]) -> Result<Self, KeyError> {
        match PublicKey::from_slice(byte_array) {
            Ok(x) => Ok(Self(x)),
            _ => Err(KeyError::BadSlice())
        }
    }

    fn as_bytes<const N: usize>(&self) -> [u8; N] {
        try_into(self.0.serialize()[0..N].to_vec())
    }

    fn raw(&self) -> PublicKey {
        self.0
    }

    /// Return a string representation of self.
    /// For ECC public keys, this is a hexadecimal representation.
    fn from_str(hex: &str) -> Result<Self, KeyError> {
        let pk = match PublicKey::from_str(hex) {
            Ok(x) => x,
            Err(_) => return Err(KeyError::BadString())
        };

        Ok( Self( pk ) )
    }
}


pub trait TapTweak {
    /// Taptweak a key given the key and optional script tree
    fn tap_tweak(&self, merkle_root: Option<TreeNode>) -> Result<Self, KeyError>
    where Self: Sized;
}

impl TapTweak for SchnorrPublicKey {
    fn tap_tweak(&self, script_tree: Option<TreeNode>) -> Result<Self, KeyError> {
        let secp = Secp256k1::new();
        let commitment = if let Some(tree) = script_tree {
            tree.merkle_root().to_vec()
        } else {
            vec![]
        };
        let tweak_value = TapTweakHash::from_key_and_tweak(self, commitment);

        //Tweak the key
        let mut tweaked_key = self.0; //clone removed
        match tweaked_key.tweak_add_assign(&secp, &tweak_value) {
            Ok(x) => {
                //Check if tweaked successfully
                let success = self.0.tweak_add_check(&secp, &tweaked_key, x, tweak_value);
                if success { return Ok( Self(tweaked_key)) }
                else { return Err(KeyError::BadArithmatic()) }
            }

            _ => Err(KeyError::BadArithmatic())
        }
    }
}

impl TapTweak for SchnorrKeyPair {
    fn tap_tweak(&self, script_tree: Option<TreeNode>) -> Result<Self, KeyError> {
        let secp = Secp256k1::new();
        let commitment = if let Some(tree) = script_tree {
            tree.merkle_root().to_vec()
        } else {
            vec![]
        };
        let tweak_value = TapTweakHash::from_key_and_tweak(&self.get_pub(), commitment);
        
        //Tweak the key
        let mut tweaked_key = self.clone();
        match tweaked_key.0.tweak_add_assign(&secp, &tweak_value) {
            Ok(_) => Ok(tweaked_key),
            Err(_) => Err(KeyError::BadArithmatic())
        }
    }
}


impl Key<lib_SchnorrPublicKey> for SchnorrPublicKey {
    //Schnorr public keys are serialized as 32 bytes
    fn as_bytes<const N: usize>(&self) -> [u8; N] {
        try_into(self.0.serialize()[0..N].to_vec())
    }

    //Create a schnoor public key from slice.
    //Fail if slice is not 32 bytes long of lib returns a failure
    fn from_slice(byte_array: &[u8]) -> Result<Self, KeyError>
    where Self: Sized {
        if byte_array.len() != 32 { println!("HERE");return Err(KeyError::BadSlice()) }

        match lib_SchnorrPublicKey::from_slice(byte_array) {
            Ok(x) => Ok(Self(x)),
            _ => Err(KeyError::BadSlice())
        }
    }

    fn raw(&self) -> lib_SchnorrPublicKey {
        self.0
    }

    /// Create self from a string representation
    /// For schnorr keys, the string representation is a hexadecimal value
    fn from_str(hex: &str) -> Result<Self, KeyError> {
        match lib_SchnorrPublicKey::from_str(hex) {
            Ok(x) => Ok(Self(x)),
            Err(_) => Err(KeyError::BadString())
        }
    }
}

impl SchnorrPublicKey {
    /// Compute a schnorr public key from a private key
    pub fn from_priv_key(key: &PrivKey) -> Self {
        //Convertion method
        key.get_pub().schnorr()
    }

    
    ///Create a schnorr public key from a key pair
    pub fn from_keypair(keypair: &lib_SchnorrKeyPair) -> Self {
        Self(lib_SchnorrPublicKey::from_keypair(&Secp256k1::new(), &keypair))
    }


    /// Serialize schnorr public key as hex string
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl Key<lib_SchnorrKeyPair> for SchnorrKeyPair {
    //Keypairs cannot be serialized
    fn as_bytes<const N: usize>(&self) -> [u8; N] { unimplemented!("Not supported") }

    //Create a schnorr key pair from a secret key slice.
    fn from_slice(byte_array: &[u8]) -> Result<Self, KeyError>
    where Self: Sized {
        if byte_array.len() != 32 { return Err(KeyError::BadSlice()) }

        match lib_SchnorrKeyPair::from_seckey_slice(&Secp256k1::new(),byte_array) {
            Ok(x) => Ok(Self(x)),
            _ => Err(KeyError::BadSlice())
        }
    }

    fn raw(&self) -> lib_SchnorrKeyPair {
        self.0
    }

    /// Create self from a string representation
    /// For SchnorrKeyPairs, the string representation is a Base58 WIF
    fn from_str(wif: &str) -> Result<Self, KeyError> {
        Self::from_priv_key(&PrivKey::from_str(wif)?)
    }
}

impl SchnorrKeyPair {
    /// Return the public key within the key pair
    pub fn get_pub(&self) -> SchnorrPublicKey {
        SchnorrPublicKey::from_keypair(&self.0)
    }

    pub fn from_priv_key(key: &PrivKey) -> Result<Self, KeyError> {
        Self::from_slice(&key.as_bytes::<32>())
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
        self.to_string().cmp(&other.to_string())
    }
}

impl PartialEq for SchnorrPublicKey {
    //Check the key bytes are equal
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes::<32>() == other.as_bytes::<32>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let derived_compressed_wif = test_key.to_string(true, Network::Bitcoin);
        let derived_uncompressed_wif = test_key.to_string(false, Network::Bitcoin);
        

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
            assert!(PrivKey::from_str(testnet_wifs[i]).unwrap().as_bytes() == expected_pk.as_bytes::<32>());
        }

        let mainnet_wifs: Vec<&str> = vec![
            "cTgPUEMicCdp7afFt7436LwduW8o3oiYVQyJMoiVscGDaLDQZGYr",
            "92y3prhVTZ6AmYBw83jNmiDqEi3DhWchDL2Rn3RosSD4JbZ3jZu"
        ];

        let expected_pk: PrivKey = PrivKey::from_slice(&[181, 243, 36, 71, 85, 202, 145, 148, 138, 199, 106, 36, 223, 13, 86, 51, 15, 97, 88, 163, 177, 89, 167, 155, 157, 230, 44, 107, 160, 171, 46, 60]).unwrap();
        
        for i in 0..mainnet_wifs.len() {
            assert!(PrivKey::from_str(mainnet_wifs[i]).unwrap().as_bytes() == expected_pk.as_bytes::<32>());
        }
    }
}