use rand::{Rng, RngCore};

use crate::{
    OsRng
};

/**
    Generates a random bits using OsRng
*/
pub fn random_bytes(size: usize) -> Vec<u8> {
    let mut osrng = osrng();
    let mut bytes: Vec<u8> = vec![0; size];
    osrng.fill_bytes(&mut bytes);
    bytes.to_vec()
}

/**
    Returns new entropy source
*/
fn osrng() -> OsRng {
    match OsRng::new() {
        Ok(g) => g,
        Err(e) => panic!("Failed to obtain OS RNG: {}", e)
    }
}