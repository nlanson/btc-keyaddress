# Bitcoin Keys and Addresses Library

This library implements keys and addresses for use with Bitcoin.

## Installation
Add this as a dependency to your ```cargo.toml```:
```
btc_keyaddress = { git = "https://github.com/nlanson/btc-keyaddress" }
```
and include this in your project
```rust
use btc_keyaddress::prelude::*;
```
## Usage Examples
### Public and Private Keys
```rust
//Create a key pair from a known WIF
let private_key = PrivKey::from_str("<your private key wif here>").unwrap();
let public_key = PubKey::from_priv_key(&private_key);

//Create a new random key pair
let private_key = PrivKey::new_rand();
let public_key = PubKey::from_priv_key(&private_key);
```

### Addresses
```rust
//todo!()
```

### Mnemonic Phrases (BIP-039)
```rust
//Create a mnemonic phrase from a known phrase
let phrase = "<your phrase seperated by spaces here>".to_string();
let mnemonic =  Mnemonic::from_phrase(phrase, Language::English, "<your passphrase>").unwrap();

//Create a new random mnemonic phrase
let mnemonic = Mnemonic::new(PhraseLength::Twelve, Language::English, "<your passphrase here>").unwrap();
```

### Hierarchal Deterministic Wallets (BIP-032)
```rust
//Create a spendable HDWallet from a mnemonic phrase
//Use WalletType::P2PKH or WalletType::P2SH_P2WPKH for legacy or non native segwit wallets.
let hdw = HDWallet::from_mnemonic(&mnemonic, WalletType::P2WPKH, 0).unwrap();
let unlocker = Unlocker::from_mnemonic(&mnemonic).unwrap();
let first_receiving_address = hdw.address_at(false, 0, Network::Bitcoin).unwrap();
let signing_key = hdw.private_key_at(false, 0, &unlocker).unwrap();

//Create a watch only HDWallet from an account level xpub key
//Since an unlocker cannot be created from an xpub key, private keys cannot be retrieved.
//However, receiving and change addresses can still be generated.
let hdw = HDWallet::from_account_public("<your xpub, ypub or zpub key>", 0).unwrap();
let first_receiving_address = hdw.address_at(false, 0, Network::Bitcoin).unwrap();


//Multisig HDWallets are coming soon!
```

## Documentation
Please clone the repo and run ```cargo doc --no-deps --document-private-items``` to auto create detailed documentation.