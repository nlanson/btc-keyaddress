/*
    Hash module include hash function necessary to hash
    a public key into an address.
*/

use crate::{
    Digest, Ripemd160, 
    Sha256, Hmac, Sha512, PBKDF2, KeyBasedHashEngine, HashEngine,
    util::try_into
};


/// Macro to create hash functions
/// Unique hash functions are implemented in their own function instead of a macro.
macro_rules! hash_function {
    // Hash function using dependencies
    ($name: ident, $lib_: ident, $out_len: expr) => {
        pub fn $name<T>(input: T) -> [u8; $out_len] 
        where T: AsRef<[u8]> {
            let mut r = $lib_::new();
            r.update(input);
            try_into(r.finalize().to_vec())
        }
    };

    // Combined hash functions
    ($name: ident, $outer: expr, $inner: expr, $out_len: expr) => {
        pub fn $name<T>(input: T) -> [u8; $out_len] 
        where T: AsRef<[u8]> {
            $outer($inner(input))
        }
    }
}

hash_function!(ripemd160, Ripemd160, 20);
hash_function!(hash160, ripemd160, sha256, 20);
hash_function!(sha256d, sha256, sha256, 32);

// SHA256 is not implemented as a macro because it uses my own implementation instead of using a dependency.
pub fn sha256<T>(input: T) -> [u8; 32]
where T: AsRef<[u8]> {
    let mut hasher = Sha256::new();
    let input = input.as_ref();
    hasher.input(input);
    hasher.hash()
}


/**
    Key deriveration function that takes in a mnemonic phrase and passphrase to produce
    a 512 bit seed.
*/
pub fn pbkdf2_hmacsha512(phrase: &Vec<String>, passphrase: &str) -> [u8; 64] {
    /*
        PBKDF2 Params:
            - Password = mnemonic sentence
            - Salt = "mnemonic"+entered passphrase.
            - rounds = 2048
            - Algorithm = HmacSha512
    */
    let mut e: PBKDF2<Hmac<Sha512>> = PBKDF2::new();
    e.input(phrase.join(" "));
    e.salt(format!("mnemonic{}", passphrase).as_bytes());
    e.iter(2048);
    e.hash()
}

/**
    Takes in an byte array input and returns the HMAC-SHA512 hash of it.
*/
pub fn hmac_sha512(data: &[u8], key: &[u8]) -> [u8; 64] {
    let mut e: Hmac<Sha512> = Hmac::new();
    e.input(data);
    e.key(key);
    e.hash()
}

/**
    Tagged hash as defined by BIP-340

    sha256( sha256("TagName") + sha256("TagName") + data )
*/
pub fn tagged_hash(tag_name: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256(tag_name);
    let mut preimage = tag_hash.to_vec();
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(data);


    
    sha256(preimage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util;

    #[test]
    fn root_seed_to_master_private_key_hmacsha512() {
        let root_seed: [u8; 64] = util::try_into(
            util::decode_02x("2e0adf79611c4e090ce5447b49dd7c77d0c1d40817ff648003cb873476f066385bf2284f041f4f06b27721675d84dfca3e0f68626b237aa68cd6be59376afb8c")
        );
        let expected_privkey_hex: &str = "24c13dbb3dc8eeec336b1f815fbd7dfd6d346e1f7b6e05df75d631a3cf90eca6";
        let expected_chaincode_hex: &str = "38baff3d60afe4a6da62c7bde576c0e564b9735aa89c46bebb14af48a86f9417";

        let extended_key: [u8; 64] = hmac_sha512(&root_seed, b"Bitcoin seed");
        let pk: [u8; 32] = util::try_into(extended_key[0..32].to_vec());
        let pk_hex: &str = &util::encode_02x(&pk);
        let cc: [u8; 32] = util::try_into(extended_key[32..64].to_vec());
        let cc_hex: &str = &util::encode_02x(&cc);

        assert_eq!(expected_privkey_hex, pk_hex);
        assert_eq!(expected_chaincode_hex, cc_hex);
    }
}