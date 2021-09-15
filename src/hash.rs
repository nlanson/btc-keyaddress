/*
    Hash module include hash function necessary to hash
    a public key into an address.
*/

use crate::{
    Digest,
    Ripemd160, Sha256, Sha512, pbkdf2,
    NewMac, Hmac, Mac, 
    util::try_into
};

/*
    Takes in an byte array and returns the ripemd160 hash of it as a byte array of length 20
*/
pub fn ripemd160<T>(input: T) -> [u8; 20]
where T: AsRef<[u8]>
{
    let mut r = Ripemd160::new();
    r.update(input);
    try_into(r.finalize().to_vec())
}

/*
    Takes in a byte array and returns the sha256 hash of it as a byte array of length 32
*/
pub fn sha256<T>(input: T) -> [u8; 32]
where T: AsRef<[u8]>
{
    let mut r = Sha256::new();
    r.update(input);
    try_into(r.finalize().to_vec())
}

/*
    Key deriveration function that takes in a mnemonic phrase and passphrase to produce
    a 512 bit seed.
*/ 
type HmacSha512 = Hmac<Sha512>; 
pub fn pbkdf2_hmacsha512(phrase: &Vec<String>, passphrase: &str) -> [u8; 64] {
    /*
        PBKDF2 Params:
            - Password = mnemonic sentence
            - Salt = "mnemonic"+entered passphrase.
            - rounds = 2048
            - Algorithm = HmacSha512
    */
    let mnemonic_sentence: String = phrase.join(" ");
    let mut res: [u8; 64] = [0; 64];
    pbkdf2::<HmacSha512>(
        mnemonic_sentence.as_bytes(),
        format!("mnemonic{}", passphrase).as_bytes(),
        2048,
        &mut res
    );
    res
}

/**
    Takes in an byte array input and returns the HMAC-SHA512 hash of it.
*/
pub fn hmac_sha512(input: &[u8]) -> [u8; 64] {
    try_into(
        HmacSha512::new_from_slice(input)
        .expect("Hmac error")
        .finalize()
        .into_bytes()
        .to_vec()
    )
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

        let extended_key: [u8; 64] = hmac_sha512(&root_seed);
        let pk: [u8; 32] = util::try_into(extended_key[0..32].to_vec());
        let pk_hex: &str = &util::encode_02x(&pk);
        let cc: [u8; 32] = util::try_into(extended_key[32..64].to_vec());
        let cc_hex: &str = &util::encode_02x(&cc);

        assert_eq!(expected_privkey_hex, pk_hex);
        assert_eq!(expected_chaincode_hex, cc_hex);
    }
}