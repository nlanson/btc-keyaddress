  

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
//Use other wallet types to use Segwit, or native Segwit
let  hdwallet = HDWallet::new(mnemonic.clone(), WalletType::P2PKH).unwrap();

//Get the extended key pair at deriveration path m/44'/0'/0'/0/0 (BIP-44)
let  xprv = hdw.get_xprv_key_at("m/44'/0'/0'/0/0").unwrap();
println!("Key pair at 'm/44'/0'/0'/0':");
println!("{}", xprv.serialize(&WalletType::P2PKH, Network::Bitcoin)); 
println!("{}", xprv.get_xpub().serialize(&WalletType::P2PKH, Network::Bitcoin));

//Get a list of addresses at a given deriveration path
let  addresses = hdw.get_addresses("m/44'/0'/0'/0/0", 10, Network::Bitcoin).unwrap();
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
let  address = Address::P2SH(&script, Network::Bitcoin).to_string().unwrap(); //Use p2wsh(&script) method to get Segwit P2WSH address
println!("{}", address);

```

  

## Documentation

  

Please clone the repo and run ```cargo doc --no-deps --document-private-items``` to auto create detailed documentation.