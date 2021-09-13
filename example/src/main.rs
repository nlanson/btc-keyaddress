use btc_keyaddress::{
    key::PubKey,
    key::PrivKey,
    address::Address
};

use btc_mnemonic::{
    mnemonic::Mnemonic,
    mnemonic::PhraseLength,
    lang::Language
};

fn main() {
    print_vals();
    println!("{:?}", Mnemonic::new(PhraseLength::Twelve, Language::English));
}

fn gen_key_pair_and_print() {
    let k = PrivKey::new_rand();
    let K = PubKey::from_priv_key(&k);

    println!("Priv: {}\nPub: {}\n", k, K);
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
