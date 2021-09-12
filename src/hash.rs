/*
    Hash module include hash function necessary to hash
    a public key into an address.
*/

use crate::{
    Ripemd160, Sha256, Digest
};

/*
    Takes in an byte array and returns the ripemd160 hash of it as a Vecu8
*/
pub fn ripemd160<T>(input: T) -> Vec<u8> 
where T: AsRef<[u8]>
{
    let mut r = Ripemd160::new();
    r.update(input);
    r.finalize().to_vec()
}

/*
    Takes in a byte array and returns the sha256 hash of it as a Vec u8
*/
pub fn sha256<T>(input: T) -> Vec<u8> 
where T: AsRef<[u8]>
{
    let mut r = Sha256::new();
    r.update(input);
    r.finalize().to_vec()
}