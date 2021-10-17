use btc_keyaddress::prelude::*;
use btc_keyaddress::hdwallet::{MultisigHDWalletBuilder, WatchOnly};

fn main() {
    //multisig_hdwallet();
}

fn print_vals() {
    let private_key: PrivKey = PrivKey::new_rand();
    let public_key: PubKey = PubKey::from_priv_key(&private_key);
    let address: String = Address::P2PKH(public_key.clone(), Network::Bitcoin).to_string().unwrap();

    println!(
        "
        Private key:  {}\n
        Public Key:   {}\n
        Address:      {}
        ", private_key.export_as_wif(true, Network::Bitcoin), public_key.hex(), address
    );
}

fn hdwallet() -> Result<(), HDWError> {
    //Create new mnemonic
    let phrase: String = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
    let mnemonic: Mnemonic = Mnemonic::from_phrase(phrase, Language::English, "").unwrap();

    //Create new HDWallet from the mnemonic created above, use Segwit P2WPKH and use account index 0.
    let hdw: HDWallet = HDWallet::from_mnemonic(&mnemonic, WalletType::P2WPKH, 0, Network::Bitcoin)?;
    
    //Get the first external receiving address for the bitcoin testnet
    for i in 0..=9 {
        println!("{}", hdw.address_at(false, i)?);
    }
    

    Ok(())
}

fn multisig_address() {
    let keys: Vec<PrivKey> = vec![
        PrivKey::from_wif("cU1mPkyNgJ8ceLG5v2zN1VkZcvDCE7VK8KrnHwW82PZb6RCq7zRq").unwrap(),
    ];
    let pkeys: Vec<PubKey> = keys.iter().map(|x| PubKey::from_priv_key(x)).collect();

    let m = 1;

    let script = Script::multisig(m, &pkeys).unwrap();
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

    let script = Script::multisig(m, &pkeys).unwrap();
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
        &Script::multisig(2, &pkeys).unwrap()
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

fn multisig_hdwallet() -> Result<(), HDWError> {
    //Create new builder instance
    let mut b = MultisigHDWalletBuilder::new();
                
    //Set wallet meta data
    //Account #0, Nested segwit, Bitcoin Mainnet
    b.set_quorum(2);
    b.set_type(MultisigWalletType::P2SH);

    //Set mnemonics
    let mnemonic_1 = Mnemonic::from_phrase("valid wife trash caution slide coach lift visual goose buzz off silly".to_string(), Language::English, "").unwrap();
    let mnemonic_2 = Mnemonic::from_phrase("salon cloth blossom below emotion buffalo bone dilemma dinosaur morning interest gentle".to_string(), Language::English, "").unwrap();
    let mnemonic_3 = Mnemonic::from_phrase("desert shock swift grant chronic invite gasp jelly round design sand liquid".to_string(), Language::English, "").unwrap();

    //Add signer mnemonics
    b.add_signer_from_mnemonic(&mnemonic_1)?;
    b.add_signer_from_mnemonic(&mnemonic_2)?;
    b.add_signer_from_mnemonic(&mnemonic_3)?;

    //Build and return
    let wallet = b.build()?;
    wallet.address_at(false, 0)?;

    Ok(())
}