
# Bitcoin Keys and Addresses Library

This library implements keys and addresses for use with Bitcoin.




## Installation

Add this as a dependency to your ```cargo.toml```:
``` 
btc_keyaddress = { git = "https://github.com/nlanson/btc-keyaddress" }
```
    
## Basic Usage Examples
```rust
use btc_keyaddress::prelude::*;

//Create a new randomm mnemonic
let mnemonic = Mnemonic::new(PhraseLength::Twelve, Language::English, "").unwrap();

//Create a mnemonic from a known seed phrease
let phrase: String = "glow laugh acquire menu anchor evil occur put hover renew calm purpose".to_string();
let mnemonic: Mnemonic = Mnemonic::from_phrase(phrase, Language::English, "").unwrap();

//Create a hierarchical deterministic wallet from the mnemonic
let hdwallet = HDWallet::new(mnemonic.clone()).unwrap();

//Get the extended key pair at deriveration path m/44'/0'/0'/0/0  (BIP-44)
let xprv = hdw.get_xprv_key_at("m/44'/0'/0'/0/0").unwrap();
println!("Key pair at 'm/44'/0'/0'/0':");
println!("{}", xprv.serialize());
println!("{}", xprv.get_xpub().serialize());

//Get a list of addresses at a given deriveration path
let addresses = hdw.get_addresses("m/44'/0'/0'/0/0", 10).unwrap();
println!("{}", addresses)'
```

  
## Documentation

Please clone the repo and run ```cargo doc --no-deps --document-private-items``` to auto create rustdocs.

  
