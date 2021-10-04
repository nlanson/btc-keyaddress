  

# Bitcoin Keys and Addresses Library

  

This library implements keys and addresses for use with Bitcoin.

  
  
  
  

## Installation
Add this as a dependency to your ```cargo.toml```:
```
btc_keyaddress = { git = "https://github.com/nlanson/btc-keyaddress" }
```

## P2PKH and P2WPKH examples:

```rust
use  btc_keyaddress::prelude::*;

//Create a new randomm mnemonic
let  mnemonic = Mnemonic::new(PhraseLength::Twelve, Language::English, "").unwrap();

//Create a mnemonic from a known seed phrease
let  phrase: String = "glow laugh acquire menu anchor evil occur put hover renew calm purpose".to_string();
let  mnemonic: Mnemonic = Mnemonic::from_phrase(phrase, Language::English, "").unwrap();

//Create a hierarchical deterministic wallet from the mnemonic
let  hdwallet = HDWallet::new(mnemonic.clone()).unwrap();

//Get the extended key pair at deriveration path m/44'/0'/0'/0/0 (BIP-44)
let  xprv = hdw.get_xprv_key_at("m/44'/0'/0'/0/0").unwrap();
println!("Key pair at 'm/44'/0'/0'/0':");
println!("{}", xprv.serialize_legacy()); //Use serialize_segwit() to mark the extended key as Segwit
println!("{}", xprv.get_xpub().serialize_legacy());

//Get a list of addresses at a given deriveration path
let  addresses = hdw.get_legacy_addresses("m/44'/0'/0'/0/0", 10).unwrap(); //Use get_segwit_addresses() to get segwit
println!("{:?}", addresses)'
```

## P2SH and P2WSH examples:
```rust
//Create 3 random private keys
let  keys: Vec<PrivKey> = vec![
	PrivKey::new_rand(),
	PrivKey::new_rand(),
	PrivKey::new_rand()
];

//Create a 2-of-3 multisig script
let  m = 2;
let  n = 3;
let  script = Script::multisig(m, n, &keys).unwrap();
 
//Encode the script as an address
let  address = Address::from_script(&script); //Use p2wsh(&script) method to get Segwit P2WSH address
println!("{}", address);

```

  

## Documentation

  

Please clone the repo and run ```cargo doc --no-deps --document-private-items``` to auto create detailed documentation.