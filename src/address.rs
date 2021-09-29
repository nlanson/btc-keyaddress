use crate:: {
    key::PubKey, key::Key,
    hash,
    bs58check,
    script::RedeemScript
};

pub struct Address;

impl Address {
    /**
        Creates a wallet address from a public key. (compressed)
        * Base58Check( Riped160( Sha256( Public Key ) ) )
    */
    pub fn from_pub_key(pk: &PubKey, compressed: bool) -> String {
        let mut pubkey_bytes: Vec<u8> = pk.as_bytes::<33>().to_vec();
        if !compressed { pubkey_bytes = pk.decompressed_bytes().to_vec(); }
        
        let mut hash: Vec<u8> = hash::sha256(&pubkey_bytes).to_vec(); //Initialise variable hash as mutable Vec<u8> and assign the sha256 hash of the public key.
        hash = hash::ripemd160(hash).to_vec(); //hash now equals the ripemd160 hash of itself. Ripemd160(Sha256(PublicKey))
        bs58check::check_encode(bs58check::VersionPrefix::BTCAddress, &hash) //Return the Bas58Check Encoded string of the hash
    }

    /**
        Creates a P2SH address from a redeem script
    */
    pub fn from_script(script: &RedeemScript) -> String {
        bs58check::check_encode(bs58check::VersionPrefix::P2ScriptAddress, &script.hash())
    }

    /**
        Does the same thing as the from_pub_key() method but uses the test net prefix
        instead of the regular prefix when encoding to base 58.
    */
    pub fn testnet_address_from_pub_key(pk: &PubKey, compressed: bool) -> String {
        let mut pubkey_bytes: Vec<u8> = pk.as_bytes::<33>().to_vec();
        if !compressed { pubkey_bytes = pk.decompressed_bytes().to_vec(); }
        
        let mut hash: Vec<u8> = hash::sha256(&pubkey_bytes).to_vec();
        hash = hash::ripemd160(hash).to_vec();
        bs58check::check_encode(bs58check::VersionPrefix::BTCTestNetAddress, &hash)

    }

    /**
        Creates a P2SH address for the test net
    */
    pub fn testnet_script_address(script: &RedeemScript) -> String {
        bs58check::check_encode(bs58check::VersionPrefix::TestnetP2SHAddress, &script.hash())
    }

    /**
        Verifies that an address is valid by checking the payload and checksum
    */
    pub fn is_valid(address: String) -> bool {
        let decoded: Vec<u8> = match bs58check::decode(&address) {
            Ok(x) => x,
            Err(_) => return false //Could return Err() here instead to provide more insight on why the address is not valid
        };
        if decoded.len() != 25 { return false }

        
        if let Ok(_) = bs58check::validate_checksum(&address) {
            return true;
        };

        false
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Address, PubKey, Key
    };
    use crate::{
        key::PrivKey,
        util::decode_02x
    };

    const TEST_PUB_KEY_HEX: &str = "0204664c60ceabd82967055ccbd0f56a1585dfbd42032656efa501c463b16fbdfe";

    fn test_pub_key() -> PubKey {
        PubKey::from_slice(&decode_02x(TEST_PUB_KEY_HEX)).unwrap()
    }

    #[test]
    fn bitcoin_address_tests() {
        let test_pubk: PubKey = test_pub_key();
        let expected_compressed_address: &str =  "124ERAK4SqHMNWXycHPautn5zDYRKr3b2E";
        let expected_uncompressed_address: &str = "1GK8NbKAtt6QvqeVMGkdbXVu9qtw74oxPz";

        let derived_compressed_address = Address::from_pub_key(&test_pubk, true);
        let derived_uncompressed_address = Address::from_pub_key(&test_pubk, false);

        //Test if the expeted and derived keys are equal
        assert_eq!(expected_compressed_address, derived_compressed_address);
        assert_eq!(expected_uncompressed_address, derived_uncompressed_address);
        assert_eq!(Address::is_valid(derived_compressed_address.to_string()), true);
        assert_eq!(Address::is_valid(derived_uncompressed_address.to_string()), true);
    }

    #[test]
    fn random_bitcoin_address_tests() {
        let rand_k:PrivKey = PrivKey::new_rand();
        let pubk: PubKey = PubKey::from_priv_key(&rand_k);
        let compressed_address = Address::from_pub_key(&pubk, true);
        let uncompressed_address = Address::from_pub_key(&pubk, false);

        //Test if the leading prefix of the address is '1'
        assert!(
            match compressed_address.chars().nth(0) {
                Some('1') => true,
                _ => false
            }
        );
        assert!(
            match uncompressed_address.chars().nth(0) {
                Some('1') => true,
                _ => false
            }
        );
    }
}