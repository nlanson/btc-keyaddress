# Bitcoin Keys and Addresses Library

## About

This library implements various aspects of Bitcoin relating to keys and addresses in Rust. The library is probably not suitable for use in anything that touches real Bitcoin. Only use if you are brave enough and know what you are doing.


This library implements:

- ECC Public and private keys (wrapped from `bitcoin-core/secp256k1` library)
- Address encoding from public key or script
- BIP-39 mnemonic phrases
- BIP-32 hierarchical deterministic wallets
- Extended public and private keys (with support for SLIP-0132 multi-sig keys)
- Single-sig HD Wallets using BIP-44/49/84 derivation paths (or even a custom path for the crazy peeps)
- Multi-sig HD Wallets using BIP-45 or 48 derivation paths
- Nested and native segwit


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
let  public_key = PubKey::from_priv_key(&private_key);

//Create a new random key pair
let private_key = PrivKey::new_rand();
let public_key = PubKey::from_priv_key(&private_key);
```

### Addresses
```rust
//P2PKH
let address = Address::P2PKH(public_key, Network::Bitcoin).to_string().unwrap();

//P2WPKH
let address = Address::P2WPKH(public_key, Network::Bitcoin).to_string().unwrap();

//P2SH nested P2WPKH
let script = Script::p2sh_p2wpkh(&public_key);
let address = Address::P2SH(script, Network::Bitcoin).to_string().unwrap();

//Multisig P2SH
let redeem_script = Script::multisig(2, 3, &public_keys).unwrap();
let address = Address::P2SH(script, Network::Bitcoin).to_string().unwrap();

//Multisig P2WSH
let redeem_script = Script::multisig(2, &public_keys).unwrap();
let address = Address:P2WSH(script, Network::Bitcoin).to_string().unwrap();

//Multisig P2SH nested P2WSH
let redeem_script = Script::multisig(2, &public_keys).unwrap();
let wrapped_script = RedeemScript::p2sh_p2wsh(&redeem_script);
let address = Address::P2SH(wrapped_script, self.network).to_string().unwrap();
```

### Mnemonic Phrases (BIP-039)
```rust
//Create a mnemonic phrase from a known phrase
let phrase = "<your phrase seperated by spaces here>".to_string();
let mnemonic = Mnemonic::from_phrase(phrase, Language::English, "<your passphrase>").unwrap();

//Create a new random mnemonic phrase
let mnemonic = Mnemonic::new(PhraseLength::Twelve, Language::English, "<your passphrase here>").unwrap();
```

### Hierarchal Deterministic Wallets (BIP-032)
```rust
//Create a spendable HDWallet from a mnemonic phrase
let mut builder = HDWalletBuilder::new();
builder.set_signer_from_mnemonic(&mnemonic).unwrap();
let wallet = builder.build().unwrap(); //Wallet type, network and account index can also be modified
let unlocker = Unlocker::from_mnemonic(&mnemonic).unwrap();

//Using the wallet
let first_receiving_address = wallet.address_at(false, 0).unwrap();
let signing_key = hdw.address_private_key(false, 0, &unlocker).unwrap(); //This signing key will be able to spend funds locked in the first receiving address

//Watch only wallets can also be made
//The funds in the wallet will not be spendable unless a valid unlocker is provided.
let mut builder = HDWalletBuilder::new();
builder.set_signer_from_xpub("<your xpub, ypub or zpub key>").unwrap(); //Builder can infer the wallet type and network from the key.
let wallet = builder.build().unwrap();

//Create a 2-of-3 multisig hd-wallet
let mut builder = MultisigHDWalletBuilder::new();
b.set_quorum(2);  //Change the value here to change the required amount of keys
b.add_signer_from_mnemonic(&mnemonic_1).unwrap();
b.add_signer_from_mnemonic(&mnemonic_2).unwrap();
b.add_signer_from_mnemonic(&mnemonic_3).unwrap(); //A max of 15 keys can be provided
let wallet = builder.build().unwrap(); //Wallet type, network, account/cosigner index and derivation paths can also be modified before build

//Using the wallet
let first_receiving_address = wallet.address_at(false, 0).unwrap();
let (key_1, key_2, key_3) = (wallet.address_private_key(false, 0, &unlocker_1).unwrap(), wallet.address_private_key(false, 0, &unlocker_2).unwrap(), wallet.address_private_key(false, 0, &unlocker_3).unwrap());
let redeem_script = wallet.redeem_script_at(false, 0).unwrap();
```
## Documentation
Please clone the repo and run ```cargo doc --no-deps --document-private-items``` to auto create detailed documentation.