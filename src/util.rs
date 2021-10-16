use std::convert::TryInto;

/*
    Decodes hex strings into a byte vector
*/
pub fn decode_02x(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("Hex decode error"))
        .collect::<Vec<u8>>()
}

/*
    Encodes byte slices into hex string
*/
pub fn encode_02x(bytes: &[u8]) -> String {
    bytes.iter().map(|x| {
        format!("{:02x}", x)
    }).collect::<String>()
}

/**
    Takes in a binary integer as a string and returns it integer value.
*/
pub fn decode_binary_string(b: &String) -> usize {
    usize::from_str_radix(b, 2).unwrap()
}

/**
    Converts a vector into an array
*/
pub fn try_into<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected {}, found {}", N, v.len()))
}

//Converts a byte array to int
pub fn as_u32_be(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 24) +
    ((array[1] as u32) << 16) +
    ((array[2] as u32) <<  8) +
    ((array[3] as u32) <<  0)
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Network {
    Bitcoin,
    Testnet
}