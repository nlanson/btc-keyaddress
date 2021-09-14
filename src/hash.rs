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