use btc_keyaddress::{
    key::{
        PubKey,
        PrivKey
    },
    address::Address,
    bip39::{
        mnemonic::Mnemonic,
        mnemonic::PhraseLength,
        lang::Language
    },
    util::encode_02x
};

fn main() {
    //print_vals();
    bip39();
    //verify_mnemonic_phrase();
    //sverify_bad_phrase();
}

fn print_vals() {
    let private_key: PrivKey = PrivKey::new_rand();
    let compressed_wif: String = private_key.export_as_wif(true);
    let uncompressed_wif: String = private_key.export_as_wif(false);
    let public_key: PubKey = PubKey::from_priv_key(&private_key);
    let compressed_address: String = Address::from_pub_key(&public_key, true);
    let uncompressed_address: String = Address::from_pub_key(&public_key, false);

    println!(
        "
        Raw private key:      {}\n
        Compressed WIF:       {}\n
        Uncompressed WIF:     {}\n
        Public Key:           {}\n
        Compressed Address:   {}\n
        Uncompressed Address: {}
        ", private_key, compressed_wif, uncompressed_wif, public_key, compressed_address, uncompressed_address
    );
}

fn bip39() {
    let mnemonic = Mnemonic::new(PhraseLength::Twelve, Language::English, "").unwrap();
    println!("Phrase: {}", mnemonic.phrase.join(" "));
    println!("Seed:   {}", encode_02x(&mnemonic.seed));
}

fn verify_mnemonic_phrase() {
    let correct_phrase: Vec<&str> = vec!["forget", "arrow", "shadow", "era", "gap", "pretty", "have", "fire", "street", "law", "valve", "sunset"];
    let phrase: Vec<String> = correct_phrase.iter().map(|x| x.to_string()).collect();
    let t = Mnemonic::verify_phrase(&phrase, &Language::English);
    match t {
        Ok(()) => println!("Checksum successful. Your seed is valid"),
        Err(x) => println!("{}", x)
    }
}

fn verify_bad_phrase() {
    let bad_phrase: Vec<&str> = vec!["arrow", "shadow", "era", "gap", "pretty", "have", "fire", "street", "law", "valve", "sunset", "forget"];
    let phrase: Vec<String> = bad_phrase.iter().map(|x| x.to_string()).collect();
    let t = Mnemonic::verify_phrase(&phrase, &Language::English);
    match t {
        Ok(()) => println!("Checksum successful. Your seed is valid"),
        Err(x) => println!("{}", x)
    }
}
