
# Bitcoin Keys and Addresses Library

This library implements keys and addresses for use with Bitcoin.




## Installation

Add this as a dependency to your ```cargo.toml```:
``` 
btc_keyaddress = { git = "https://github.com/nlanson/btc-keyaddress" }
```
    
## Basic Usage Examples
```rust
//Create a new randomm mnemonic
let mnemonic = Mnemonic::new(PhraseLength::Twelve, Language::English, "").unwrap();

//Create a mnemonic from a known seed phrease
let phrase: String = "glow laugh acquire menu anchor evil occur put hover renew calm purpose".to_string();
let mnemonic: Mnemonic = Mnemonic::from_phrase(phrase, Language::English, "").unwrap();

//Create a hierarchical deterministic wallet from the mnemonic
let hdwallet = HDWallet::new(mnemonic.clone()).unwrap();

//Get the extended key pair at deriveration path m/44'/0'/0'/0  (BIP-44)
let (xprv, xpub) = match hdw.mpriv_key().derive_from_path("m/44'/0'/0'/0") {
    Ok(x) => { 
        (x, x.get_xpub())
    },
    Err(x) => panic!("Could not derive key pair")
};

//Serialise an extended key
let serialized = xprv.serialize();
println!("{}", serialized);

//Print the address of an extended key
let address = xpub.get_address();
println!("{}", address);
```

  
## Documentation

Please clone the repo and run ```cargo doc --no-deps --document-private-items``` to auto create rustdocs.

  
