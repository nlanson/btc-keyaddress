use btc_keyaddress::prelude::*;
use btc_keyaddress::hdwallet::WatchOnly;

fn main() {
    //print_vals();
    //bip39();
    //println!("{:?}", verify_mnemonic_phrase());
    //println!("{:?}", verify_bad_phrase());
    //hdwallet().unwrap()
    //multisig_address();
    //segwit_hdwallet();
    //p2sh_p2wsh();
    xpub_watch_only();
}

fn print_vals() {
    let private_key: PrivKey = PrivKey::new_rand();
    let compressed_wif: String = private_key.export_as_wif(true, Network::Testnet);
    let uncompressed_wif: String = private_key.export_as_wif(false, Network::Testnet);
    let public_key: PubKey = PubKey::from_priv_key(&private_key);
    let compressed_address: String = Address::P2PKH(public_key.clone(), Network::Testnet).to_string().unwrap();

    println!(
        "
        Raw private key:      {}\n
        Compressed WIF:       {}\n
        Uncompressed WIF:     {}\n
        Public Key:           {}\n
        Compressed Address:   {}
        ", private_key, compressed_wif, uncompressed_wif, public_key, compressed_address
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
    let hdw: HDWallet = HDWallet::new(mnemonic.clone(), WalletType::P2PKH).unwrap();

    println!("
    mnemonic: {}\n
    mpriv: {}\n
    mpub:  {}\n
    address (m/0/0):   {}
    ", mnemonic.phrase.join(" "),
       hdw.mpriv_key().serialize(&WalletType::P2PKH, Network::Bitcoin),
       hdw.mpub_key().serialize(&WalletType::P2PKH, Network::Bitcoin),
       Address::P2PKH(
           hdw.mpriv_key()
           .get_xchild(ChildOptions::Normal(0))?
           .get_xchild(ChildOptions::Normal(0))?
           .get_pub(),
           Network::Bitcoin
        )
    );

    let xprv = hdw.get_xprv_key_at("m/44'/0'/0'/0/0").unwrap();
    println!("Key pair at 'm/44'/0'/0'/0':");
    println!("{}", xprv.get_prv().export_as_wif(true, Network::Bitcoin));
    println!("{}", xprv.get_xpub().serialize(&WalletType::P2PKH, Network::Bitcoin));
    println!("{:?}", hdw.get_addresses("m/44'/0'/0'/0/0", 10, Network::Bitcoin).unwrap());
    

    Ok(())
}

fn multisig_address() {
    let keys: Vec<PrivKey> = vec![
        PrivKey::from_wif("cU1mPkyNgJ8ceLG5v2zN1VkZcvDCE7VK8KrnHwW82PZb6RCq7zRq").unwrap(),
    ];
    let pkeys: Vec<PubKey> = keys.iter().map(|x| PubKey::from_priv_key(x)).collect();

    let m = 1;
    let n = 1;

    let script = Script::multisig(m, n, &pkeys).unwrap();
    println!("{:02x?}", script.code);
    let address = Address::P2SH(script, Network::Testnet);

    println!("
        Address: {}\n
        Key 1: {}
    ", address,
       keys[0].export_as_wif(true, Network::Testnet)
    );
}

fn segwit_hdwallet() {
    let mnemonic: Mnemonic = Mnemonic::new(PhraseLength::Twelve, Language::English, "").unwrap();
    let hdw = HDWallet::new(mnemonic.clone(), WalletType::P2PKH).unwrap();
    let addresses = hdw.get_addresses("m/84'/0'/0'/0/0", 10, Network::Bitcoin).unwrap();

    println!("Phrase: {}", mnemonic.phrase.join(" "));
    println!("Addresses: {:?}", addresses);
}

fn p2wsh_address() {
    let keys = vec![
        PrivKey::from_wif("cPUFTUmN7R1vqyGetUfEv8Az5vTNAipHyCLZq8kpJS355NmB44BJ").unwrap(),
        PrivKey::from_wif("cNReSU1dagjXPo4ky99PaXbW4NobKWoppb5AVaCpjjQsJ2uRgoDe").unwrap(),
        PrivKey::from_wif("cSTgRcaiVDpG4yrsECW59wfUwYjTYsHh4UCcUhz2WatYWd18KDso").unwrap()
    ];
    let pkeys: Vec<PubKey> = keys.iter().map(|x| PubKey::from_priv_key(x)).collect();

    let m = 2;
    let n = 3;

    let script = Script::multisig(m, n, &pkeys).unwrap();
    let address = Address::P2WSH(script.clone(), Network::Testnet).to_string().unwrap();

    println!("
        Address: {}\n
        Script: {}\n
        Key 1: {}\n
        Key 2: {}\n
        Key 3: {}\n
    ", address,
       encode_02x(&script.code),
       encode_02x(&PubKey::from_priv_key(&keys[0]).as_bytes::<33>()),
       encode_02x(&PubKey::from_priv_key(&keys[1]).as_bytes::<33>()),
       encode_02x(&PubKey::from_priv_key(&keys[2]).as_bytes::<33>())
    );
}

fn p2sh_p2wsh() {
    let keys = vec![
        PrivKey::new_rand(),
        PrivKey::new_rand(),
        PrivKey::new_rand()
    ];
    let pkeys: Vec<PubKey> = keys.iter().map(|x| PubKey::from_priv_key(x)).collect();

    let script = Script::p2sh_p2wsh(
        &Script::multisig(2, 3, &pkeys).unwrap()
    );
    let address = Address::P2SH(script, Network::Testnet).to_string().unwrap();

    println!("
        Address: {}\n
        Key 1: {}\n
        Key 2: {}\n
        Key 3: {}\n
    ", address,
       keys[0].export_as_wif(true, Network::Testnet),
       keys[1].export_as_wif(true, Network::Testnet),
       keys[2].export_as_wif(true, Network::Testnet),
    );
}

fn xpub_watch_only() -> Result<(), HDWError> {
    let mnemonic = Mnemonic::from_phrase("bridge hawk weather prefer short follow renew judge gadget dial pepper liquid".to_string(), Language::English, "").unwrap();
    let hdw = btc_keyaddress::hdwallet::HDWallet2::from_mnemonic(&mnemonic, WalletType::P2WPKH).unwrap();
    let unlocker = btc_keyaddress::hdwallet::Unlocker::from_mnemonic(&mnemonic).unwrap();

    //let mpub = hdw.master_public_key().serialize(&WalletType::P2WPKH, Network::Bitcoin);
    let mpub = hdw.address_at(false, 0, Network::Bitcoin);
    println!("{:?}", mpub);

    Ok(())
}