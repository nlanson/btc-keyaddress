use btc_keyaddress::{key::Key, prelude::*};

fn main() {
    //print_vals();
    //bip39();
    //println!("{:?}", verify_mnemonic_phrase());
    //println!("{:?}", verify_bad_phrase());
    //hdwallet().unwrap()
    p2wpkh();
    p2wsh();
}

fn print_vals() {
    let private_key: PrivKey = PrivKey::new_rand();
    let compressed_wif: String = private_key.export_as_wif(true, true);
    let uncompressed_wif: String = private_key.export_as_wif(false, true);
    let public_key: PubKey = PubKey::from_priv_key(&private_key);
    let compressed_address: String = Address::testnet_address_from_pub_key(&public_key, true);
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

fn bip39() -> Result<Mnemonic, MnemonicErr> {
    let mnemonic = Mnemonic::new(PhraseLength::Twelve, Language::English, "")?;
    Ok(mnemonic)
}

fn verify_mnemonic_phrase() -> Result<(), MnemonicErr> {
    let correct_phrase: Vec<&str> = vec!["forget", "arrow", "shadow", "era", "gap", "pretty", "have", "fire", "street", "law", "valve", "sunset"];
    let phrase: Vec<String> = correct_phrase.iter().map(|x| x.to_string()).collect();
    Mnemonic::verify_phrase(&phrase, &Language::English)?;

    Ok(())
}

fn verify_bad_phrase()-> Result<(), MnemonicErr> {
    let bad_phrase: Vec<&str> = vec!["govern", "shadow", "era", "gap", "pretty", "have", "fire", "street", "law", "valve", "sunset", "forget"];
    let phrase: Vec<String> = bad_phrase.iter().map(|x| x.to_string()).collect();
    Mnemonic::verify_phrase(&phrase, &Language::English)?; //Will panic on unwrap

    Ok(())
}

fn hdwallet() -> Result<(), HDWError> {
    let phrase: String = "glow laugh acquire menu anchor evil occur put hover renew calm purpose".to_string();
    let mnemonic: Mnemonic = Mnemonic::from_phrase(phrase, Language::English, "").unwrap();
    //let mnemonic: Mnemonic = Mnemonic::new(PhraseLength::Twelve, Language::English, "").unwrap();
    let hdw: HDWallet = HDWallet::new(mnemonic.clone()).unwrap();

    println!("
    mnemonic: {}\n
    mpriv: {}\n
    mpub:  {}\n
    address (m/0/0):   {}
    ", mnemonic.phrase.join(" "),
       hdw.mpriv_key().serialize(),
       hdw.mpub_key().serialize(),
       Address::from_pub_key(
           &hdw.mpriv_key()
           .get_xchild(ChildOptions::Normal(0))?
           .get_xchild(ChildOptions::Normal(0))?
           .get_pub(),
           true
        )
    );

    let xprv = hdw.get_xprv_key_at("m/44'/0'/0'/0/0").unwrap();
    println!("Key pair at 'm/44'/0'/0'/0':");
    println!("{}", xprv.get_prv().export_as_wif(true, false));
    println!("{}", xprv.get_xpub().serialize());
    println!("{:?}", hdw.get_addresses("m/44'/0'/0'/0/0", 10).unwrap());
    

    Ok(())
}

fn p2wpkh() {
    let private_key: PrivKey = PrivKey::new_rand();
    let p2wpkh_address = Address::p2wpkh(&PubKey::from_priv_key(&private_key)).unwrap();

    println!("{}", encode_02x(&PubKey::from_priv_key(&private_key).as_bytes::<33>()));
    println!("{}", p2wpkh_address);
    println!("{}", p2wpkh_address.len());
}

fn p2wsh() {
    let script: RedeemScript = RedeemScript::new(vec![
        0x6a, 0x29, 0x05, 0x20, 0x03
    ]);

    let p2wsh_address = Address::p2wsh(&script).unwrap();
    println!("{}", p2wsh_address);
    println!("{}", p2wsh_address.len());
}
