use crate:: {
    key::PubKey, key::Key,
    hash,
    encoding::{
        bs58check as bs58check,
        bech32 as bech32
    },
    script::Script
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
    pub fn from_script(script: &Script) -> String {
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
    pub fn testnet_script_address(script: &Script) -> String {
        bs58check::check_encode(bs58check::VersionPrefix::TestnetP2SHAddress, &script.hash())
    }

    /**
        Create a mainnet P2WPKH address from a public key
    */
    pub fn p2wpkh(pk: &PubKey) -> Result<String, bech32::Bech32Err>  {
        let hash = hash::hash160(&pk.as_bytes::<33>());
        Ok(bech32::encode_to_address(&hash, "mainnet")?)
    }

    /**
        Create a testnet P2WPKH address from a public key
    */
    pub fn testnet_p2wpkh(pk: &PubKey) -> Result<String, bech32::Bech32Err>  {
        let hash = hash::hash160(&pk.as_bytes::<33>());
        Ok(bech32::encode_to_address(&hash, "testnet")?)
    }

    /**
        Create mainnet P2WSH addresses from a redeem script
    */
    pub fn p2wsh(script: &Script) -> Result<String, bech32::Bech32Err> {
        let hash = hash::sha256(script.script.clone());
        Ok(bech32::encode_to_address(&hash, "mainnet")?)
    }

    /**
        Create mainnet P2WSH addresses from a redeem script
    */
    pub fn testnet_p2wsh(script: &Script) -> Result<String, bech32::Bech32Err> {
        let hash = hash::sha256(script.script.clone());
        Ok(bech32::encode_to_address(&hash, "testnet")?)
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
        util::decode_02x,
        script::Script
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

    #[test]
    fn testnet_legacy_address_tests() {
        //Test data test
        let private_key: PrivKey = PrivKey::from_wif("cNShtSaCAzPPSFgm5LiGUhkuyBhJyV4jQqYXP3asyXK9k8uhiZdx").unwrap();
        let public_key: PubKey = PubKey::from_priv_key(&private_key);
        let derived_address: String = Address::testnet_address_from_pub_key(&public_key, true);
        let expected_address: String = "msSJzRfQb2T3hvws3vRhqtK2Ao39cabEa2".to_string();

        assert!(derived_address == expected_address);

        //Random tests
        for _i in 0..5 {
            let k = PrivKey::new_rand();
            let pk = PubKey::from_priv_key(&k);
            let address = Address::testnet_address_from_pub_key(&pk, true);
            match address.chars().nth(0) {
                Some('m') | Some('n') => assert!(true),
                _ => assert!(false)
            }
        }
    }

    #[test]
    fn p2sh_address_tests() {
        //Test data test
        let script: Script = Script::new(vec![0x6a, 0x29, 0x05, 0x20, 0x03]);
        let derived_address = Address::from_script(&script);
        let expected_address = "33SjjXog5Tqm3kCYNGCQBH46gc48a4SUXn".to_string();
        assert!(derived_address == expected_address);

        //Random mainnet tests
        for i in 0..5 {
            let script: Script = Script::new(vec![i; 5]);
            let address = Address::from_script(&script);
            match address.chars().nth(0) {
                Some('3') => assert!(true),
                _ => assert!(false)
            }
        }

        //Random testnet tests
        for i in 0..5 {
            let script: Script = Script::new(vec![i; 5]);
            let address = Address::testnet_script_address(&script);
            match address.chars().nth(0) {
                Some('2') => assert!(true),
                _ => assert!(false)
            }
        }
    }

    #[test]
    fn p2wpkh_address_tests() {
        let key_1: PrivKey = PrivKey::from_wif("cPYWWA7yv4ivb2ueWJP6SKr6rSJiT6JfGkdVrgvhrWR7soE8RxBG").unwrap();
        let pk1 = PubKey::from_priv_key(&key_1);
        let derived_address_1 = Address::testnet_p2wpkh(&pk1).unwrap();
        let expected_address_1 = "tb1qxauw2dslmtgdyzw73gtv9mzv5erp3xf7mt83vq".to_string();
        assert!(derived_address_1 == expected_address_1);
        
        let key_2: PrivKey = PrivKey::from_wif("cRzmfLNVsbHp5MYJhY8xz6DaYJBUgSKQL8jwU2xL3su6GScPgxsb").unwrap();
        let pk2 = PubKey::from_priv_key(&key_2);
        let derived_address_2 = Address::testnet_p2wpkh(&pk2).unwrap();
        let expected_address_2 = "tb1qj8rvxxnzkdapv3rueazzyn434duv5q5ep3ze5e".to_string();
        assert!(derived_address_2 == expected_address_2);
    }

    #[test]
    fn p2wsh_address_tests() {
        let redeem_script: Script = Script::new(vec![0x6a, 0x29, 0x05, 0x20, 0x03]);
        let derived_mainnet_address = Address::p2wsh(&redeem_script).unwrap();
        let expected_mainnet_address = "bc1q4sr2gyed4ww8zm0t9ktn47qxlu2nhl5ejkf6fjzfttnsjvxdkqjqe7yhq9".to_string();
        let derived_testnet_address = Address::testnet_p2wsh(&redeem_script).unwrap();
        let expected_testnet_address = "tb1q4sr2gyed4ww8zm0t9ktn47qxlu2nhl5ejkf6fjzfttnsjvxdkqjqwkjc62".to_string();

        assert!(derived_mainnet_address == expected_mainnet_address);
        assert!(derived_testnet_address == expected_testnet_address);
    }
}