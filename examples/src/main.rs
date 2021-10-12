use btc_keyaddress::prelude::*;
use btc_keyaddress::hdwallet::WatchOnly;

fn main() {
    
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

fn hdwallet() -> Result<(), HDWError> {
    //Create new mnemonic
    let phrase: String = "glow laugh acquire menu anchor evil occur put hover renew calm purpose".to_string();
    let mnemonic: Mnemonic = Mnemonic::from_phrase(phrase, Language::English, "").unwrap();

    //Create new HDWallet from the mnemonic created above, use Segwit P2WPKH and use account index 0.
    let hdw: HDWallet = HDWallet::from_mnemonic(&mnemonic, WalletType::P2WPKH, 0, Network::Bitcoin)?;
    
    //Get the first external receiving address for the bitcoin testnet
    hdw.address_at(false, 0);

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