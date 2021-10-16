# Bitcoin Keys and Addresses Library
## About
This library implements various aspects of Bitcoin relating to keys and addresses in Rust. The library is probably not suitable for use in anything that touches real Bitcoin. Only use if you are brave enough and know what you are doing.

This library implements:
 - Public and private keys
 - Address derivation from public key and script
 - BIP-39 mnemonic phrases
 - BIP-32 HD Wallets
 - Extended public and private keys (with support for SLIP-0132 multi-sig keys)
 - Single-sig HD Wallets using BIP-44/49/84 derivation paths (or even a custom path for the crazy peeps)
 - Multi-sig HD Wallets using BIP-45 or 48 derivation paths
 - Segwit


## Installation
Add this as a dependency to your ```cargo.toml```:
```
btc_keyaddress = { git = "https://github.com/nlanson/btc-keyaddress" }
```
and include this in your project
```rust
use  btc_keyaddress::prelude::*;
```
## Usage Examples
### Public and Private Keys
```rust
//Create a key pair from a known WIF
let  private_key = PrivKey::from_str("<your private key wif here>").unwrap();
let  public_key = PubKey::from_priv_key(&private_key);

//Create a new random key pair
let  private_key = PrivKey::new_rand();
let  public_key = PubKey::from_priv_key(&private_key);
```
### Addresses
```rust
//P2PKH
let  address = Address::P2PKH(public_key, Network::Bitcoin).to_string().unwrap();

//P2WPKH
let  address = Address::P2WPKH(public_key, Network::Bitcoin).to_string().unwrap();

//P2SH nested P2WPKH
let  script = Script::p2sh_p2wpkh(&public_key);
let  address = Address::P2SH(script, Network::Bitcoin).to_string().unwrap();

//Multisig P2SH
let  redeem_script = Script::multisig(2, 3, &public_keys).unwrap();
let  address = Address::P2SH(script, Network::Bitcoin).to_string().unwrap();

//Multisig P2WSH
let  redeem_script = Script::multisig(2, &public_keys).unwrap();
let  address = Address:P2WSH(script, Network::Bitcoin).to_string().unwrap();
```
### Mnemonic Phrases (BIP-039)
```rust
//Create a mnemonic phrase from a known phrase
let  phrase = "<your phrase seperated by spaces here>".to_string();
let  mnemonic = Mnemonic::from_phrase(phrase, Language::English, "<your passphrase>").unwrap();

//Create a new random mnemonic phrase
let  mnemonic = Mnemonic::new(PhraseLength::Twelve, Language::English, "<your passphrase here>").unwrap();
```
### Hierarchal Deterministic Wallets (BIP-032)
```rust
//Create a spendable HDWallet from a mnemonic phrase
//Use WalletType::P2PKH or WalletType::P2SH_P2WPKH for legacy or non native segwit wallets.
let  hdw = HDWallet::from_mnemonic(&mnemonic, WalletType::P2WPKH, 0, Network::Bitcoin).unwrap();
let  unlocker = Unlocker::from_mnemonic(&mnemonic).unwrap();
let  first_receiving_address = hdw.address_at(false, 0, Network::Bitcoin).unwrap();
let  signing_key = hdw.address_private_key(false, 0, &unlocker).unwrap();
let  custom_path_address = hdw.custom_path_extended_private_key("<a non standard derivation path>", &unlocker)?.get_address(&hdw.wallet_type, hdw.network);

//Create a watch only HDWallet from an account level xpub key
//Since an unlocker cannot be created from an xpub key, private keys cannot be retrieved.
//However, receiving and change addresses can still be generated.
let  hdw = HDWallet::from_account_public("<your xpub, ypub or zpub key>", 0).unwrap();
let  first_receiving_address = hdw.address_at(false, 0, Network::Bitcoin).unwrap();

//Multisig HDWallets are very coming soon!
```

## Documentation
Please clone the repo and run ```cargo doc --no-deps --document-private-items``` to auto create detailed documentation.