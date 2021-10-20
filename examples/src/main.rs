use btc_keyaddress::prelude::*;

fn main() {
    //multisig_hdwallet();
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