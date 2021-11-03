use crate:: {
    encoding::{
        bech32::Bech32Err,
        bs58check as bs58check
    },
    hash,
    key::{
        Key,
        PubKey,
        SchnorrPublicKey
    },
    script::{
        RedeemScript,
        WitnessProgram
    },
    util::Network
};

pub enum Address {
    P2PKH(PubKey, Network),
    P2SH(RedeemScript, Network),
    P2WPKH(PubKey, Network),
    P2WSH(RedeemScript, Network),
    P2TR(SchnorrPublicKey, Network)  //The public key here is the tweaked public key
}

#[derive(Debug)]
pub enum AddressErr {
    Bech32Err
}

impl Address {
    pub fn to_string(&self) -> Result<String, AddressErr> {
        match self {
            Address::P2PKH(k, n) => Ok(Self::p2pkh(k, n)),
            Address::P2SH(s, n) => Ok(Self::p2sh(s, n)),
            Address::P2WPKH(k, n) => Ok(
                match Self::p2wpkh(k, n) {
                    Ok(x) => x,
                    Err(_) => return Err(AddressErr::Bech32Err)
                }
            ),
            Address::P2WSH(s, n) => Ok(
                match Self::p2wsh(s, n) {
                    Ok(x) => x,
                    Err(_) => return Err(AddressErr::Bech32Err)
                }
            ),
            Address::P2TR(k, n) => Ok( 
                match Self::p2tr(k, n) {
                    Ok(x) => x,
                    Err(_) => return Err(AddressErr::Bech32Err)
                }
            )
        }
    }

    fn p2pkh(pk: &PubKey, network: &Network) -> String {
        match network {
            Network::Bitcoin => bs58check::check_encode(bs58check::VersionPrefix::BTCAddress, &pk.hash160()),
            Network::Testnet => bs58check::check_encode(bs58check::VersionPrefix::BTCTestNetAddress, &pk.hash160())
        }
    }

    fn p2sh(script: &RedeemScript, network: &Network) -> String {
        match network {
            Network::Bitcoin => bs58check::check_encode(bs58check::VersionPrefix::P2ScriptAddress, &script.hash()),
            Network::Testnet => bs58check::check_encode(bs58check::VersionPrefix::TestnetP2SHAddress, &script.hash())
        }
    }

    fn p2wpkh(pk: &PubKey, network: &Network) -> Result<String, Bech32Err> {
        let witness_program = WitnessProgram::new(0, pk.hash160()).unwrap();
        Ok(witness_program.to_address(network)?)
    }

    fn p2wsh(script: &RedeemScript, network: &Network) -> Result<String, Bech32Err> {
        let hash = hash::sha256(script.code.clone()).to_vec();

        let witness_program = WitnessProgram::new(0, hash).unwrap();
        Ok(witness_program.to_address(network)?)
    }

    fn p2tr(tweaked_public_key: &SchnorrPublicKey, network: &Network) -> Result<String, Bech32Err> {
        let bytes = tweaked_public_key.as_bytes::<32>().to_vec();
        let witness_program = WitnessProgram::new(1, bytes).unwrap();
        Ok(witness_program.to_address(network)?)
    }

    /**
        Verifies that an address is valid by checking the payload and checksum.
        Only works for legacy addresses
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
        Address, PubKey, Key,
        AddressErr
    };
    use crate::{
        key::{
            KeyError,
            PrivKey,
            SchnorrPublicKey
        },
        script::RedeemScript,
        taproot::{
            taproot_tweak_pubkey
        },
        util::Network,
        util::decode_02x
    };

    const TEST_PUB_KEY_HEX: &str = "0204664c60ceabd82967055ccbd0f56a1585dfbd42032656efa501c463b16fbdfe";

    fn test_pub_key() -> PubKey {
        PubKey::from_slice(&decode_02x(TEST_PUB_KEY_HEX)).unwrap()
    }

    #[test]
    fn p2pkh() {
        let test_pubk: PubKey = test_pub_key();

        let expected_compressed_address: &str =  "124ERAK4SqHMNWXycHPautn5zDYRKr3b2E";
        let derived_compressed_address = Address::P2PKH(test_pubk, Network::Bitcoin).to_string().unwrap();


        //Test if the expeted and derived keys are equal
        assert_eq!(expected_compressed_address, derived_compressed_address);
        assert_eq!(Address::is_valid(derived_compressed_address.to_string()), true);

    }

    #[test]
    fn random_p2pkh() {
        let rand_k:PrivKey = PrivKey::new_rand();
        let pubk: PubKey = PubKey::from_priv_key(&rand_k);
        let compressed_address = Address::P2PKH(pubk, Network::Bitcoin).to_string().unwrap();

        //Test if the leading prefix of the address is '1'
        assert!(
            match compressed_address.chars().nth(0) {
                Some('1') => true,
                _ => false
            }
        );
    }

    #[test]
    fn testnet_p2pkh() {
        //Test data test
        let private_key: PrivKey = PrivKey::from_wif("cNShtSaCAzPPSFgm5LiGUhkuyBhJyV4jQqYXP3asyXK9k8uhiZdx").unwrap();
        let public_key: PubKey = PubKey::from_priv_key(&private_key);
        let derived_address: String = Address::P2PKH(public_key, Network::Testnet).to_string().unwrap();
        let expected_address: String = "msSJzRfQb2T3hvws3vRhqtK2Ao39cabEa2".to_string();

        assert!(derived_address == expected_address);

        //Random tests
        for _i in 0..5 {
            let k = PrivKey::new_rand();
            let pk = PubKey::from_priv_key(&k);
            let address = Address::P2PKH(pk, Network::Testnet).to_string().unwrap();
            match address.chars().nth(0) {
                Some('m') | Some('n') => assert!(true),
                _ => assert!(false)
            }
        }
    }

    #[test]
    fn p2sh() {
        //Test data test
        let script: RedeemScript = RedeemScript::new(vec![0x6a, 0x29, 0x05, 0x20, 0x03]);
        let derived_address = Address::P2SH(script, Network::Bitcoin).to_string().unwrap();
        let expected_address = "33SjjXog5Tqm3kCYNGCQBH46gc48a4SUXn";
        assert!(derived_address == expected_address);

        //Random mainnet tests
        for i in 0..5 {
            let script: RedeemScript = RedeemScript::new(vec![i; 5]);
            let address = Address::P2SH(script, Network::Bitcoin).to_string().unwrap();
            match address.chars().nth(0) {
                Some('3') => assert!(true),
                _ => assert!(false)
            }
        }

        //Random testnet tests
        for i in 0..5 {
            let script: RedeemScript = RedeemScript::new(vec![i; 5]);
            let address = Address::P2SH(script, Network::Testnet).to_string().unwrap();
            match address.chars().nth(0) {
                Some('2') => assert!(true),
                _ => assert!(false)
            }
        }
    }

    #[test]
    fn p2wpkh() {
        let key_1: PrivKey = PrivKey::from_wif("cPYWWA7yv4ivb2ueWJP6SKr6rSJiT6JfGkdVrgvhrWR7soE8RxBG").unwrap();
        let pk1 = PubKey::from_priv_key(&key_1);
        let derived_address_1 = Address::P2WPKH(pk1, Network::Testnet).to_string().unwrap();
        let expected_address_1 = "tb1qxauw2dslmtgdyzw73gtv9mzv5erp3xf7mt83vq".to_string();
        assert_eq!(derived_address_1, expected_address_1);
        
        let key_2: PrivKey = PrivKey::from_wif("cRzmfLNVsbHp5MYJhY8xz6DaYJBUgSKQL8jwU2xL3su6GScPgxsb").unwrap();
        let pk2 = PubKey::from_priv_key(&key_2);
        let derived_address_2 = Address::P2WPKH(pk2, Network::Testnet).to_string().unwrap();
        let expected_address_2 = "tb1qj8rvxxnzkdapv3rueazzyn434duv5q5ep3ze5e".to_string();
        assert_eq!(derived_address_2, expected_address_2);
    }

    #[test]
    fn p2wsh() {
        let redeem_script: RedeemScript = RedeemScript::new(vec![0x6a, 0x29, 0x05, 0x20, 0x03]);
        let derived_mainnet_address = Address::P2WSH(redeem_script.clone(), Network::Bitcoin).to_string().unwrap();
        let expected_mainnet_address = "bc1q4sr2gyed4ww8zm0t9ktn47qxlu2nhl5ejkf6fjzfttnsjvxdkqjqe7yhq9".to_string();
        let derived_testnet_address = Address::P2WSH(redeem_script.clone(), Network::Testnet).to_string().unwrap();
        let expected_testnet_address = "tb1q4sr2gyed4ww8zm0t9ktn47qxlu2nhl5ejkf6fjzfttnsjvxdkqjqwkjc62".to_string();

        assert!(derived_mainnet_address == expected_mainnet_address);
        assert!(derived_testnet_address == expected_testnet_address);
    }

    #[test]
    fn p2tr() -> Result<(), KeyError> {
        let internal_key = SchnorrPublicKey::from_str("cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115")?;
        let (_, tweaked_key) = taproot_tweak_pubkey(&internal_key, b"").unwrap();
        let address = Address::P2TR(tweaked_key, Network::Bitcoin).to_string().unwrap();

        assert_eq!(tweaked_key.hex(), "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c");
        assert_eq!(address, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
        Ok(())
    }
}