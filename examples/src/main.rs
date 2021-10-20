use btc_keyaddress::prelude::*;
use btc_keyaddress::hdwallet::{ MultisigHDWalletBuilder, WatchOnly };

fn main() {
    //multisig_hdwallet();
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


fn multisig_hdwallet() -> Result<(), HDWError> {
    //Create new builder instance
    let mut b = MultisigHDWalletBuilder::new();
                
    //Set wallet meta data
    //Account #0, Nested segwit, Bitcoin Mainnet
    b.set_quorum(2);

    //Set mnemonics
    let mnemonic_1 = Mnemonic::new(PhraseLength::Twelve, Language::English, "").unwrap();
    let mnemonic_2 = Mnemonic::new(PhraseLength::Twelve, Language::English, "").unwrap();
    let mnemonic_3 = Mnemonic::new(PhraseLength::Twelve, Language::English, "").unwrap();

    //Add mnemonics
    b.add_signer_from_mnemonic(&mnemonic_1)?;
    b.add_signer_from_mnemonic(&mnemonic_2)?;
    b.add_signer_from_mnemonic(&mnemonic_3)?;

    //Build
    let wallet = b.build()?;

    //Print the mnemonics
    println!(
        "Mmemonics:\n    {}\n    {}\n    {}",
        mnemonic_1.phrase.join(" "), mnemonic_2.phrase.join(" "), mnemonic_3.phrase.join(" "),
    );

    //Print the first 10 receiving addresses
    println!("Addresses:");
    for i in 0..10 {
        println!("    {}", wallet.address_at(false, i)?);
    }

    Ok(())
}