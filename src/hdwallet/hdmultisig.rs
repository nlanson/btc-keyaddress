/*
    Module implementing Multisig HD Wallet data structures

    Todo:.
        - Multisig address generator and key extracting should be working (no unit tests)
          but is very clunky. This could be refactored into a better `builder` struct similar
          to btc-tx's tx-builder where multisig wallets are `built` with methods.
        - Split BIP-48 and BIP-48. This can be splitting the two into completely different structs or
          something a little less strict like using different traits for the two.

          eg.
                struct MultiSigWalletBuilder {
                    wallet_type: Option<MultisigWalletType>,
                    quorum: Option<u8>,
                    network: Option<Network>,
                    account_index: Option<u32>,
                    signers: Vec<Xprv>
                }

                impl MultisigWalletBuilder {
                    pub fn new() -> Self {
                        Self {
                            wallet_type: None,
                            quorum: None,
                            network: None,
                            account_index: None,
                            signers: vec![]
                        }
                    }

                    pub fn add_signer(&mut self, signer: Xprv) -> Result<(), HDWError> {
                        self.signers.push(signer);
                        Ok(())
                    }

                    ... (more methods on setting quorum, account index, network, wallet type etc...) ...

                    pub fn build(&self) -> MultisigHDWallet {
                        //Build the multisig hdwallet from info gathered.
                        //If any information is missing, fail the build
                    }
                }
*/

use crate::{
    address::Address,
    bip39::Mnemonic,
    key::{
        PrivKey, PubKey, Key
    },
    script::Script,
    util::Network
};
use super::{
    HDWallet,
    WalletType,
    HDWError,
    ExtendedKey,
    Xprv, Xpub,
    Path,
    ChildOptions,
    Unlocker
};

#[derive(Copy, Clone, Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum MultisigWalletType {
    P2SH = 0,
    P2WSH = 2,
    P2SH_P2WSH = 1
}

impl MultisigWalletType {
    //Given a vector of extended keys, return the type of multisig wallet to use.
    //If all of the keys are the same type, return the MultisigWalletType.
    //If even one of the keys is a different type, return an error.
    pub fn from_xkeys(keys: &Vec<&str>) -> Result<Self, HDWError> {
        //Get the wallet type for each individual key as if it was a PKH wallet
        let key_type = keys.iter().map(|x| {
            WalletType::from_xkey(x).unwrap()
        }).collect::<Vec<WalletType>>();

        //If all the wallet types are equal to the first wallet type,
        //then return the multisig wallet type of the first key
        if key_type.iter().all(|t| *t == key_type[0]) {
            return Ok(match key_type[0] {
                WalletType::P2PKH => MultisigWalletType::P2SH,
                WalletType::P2SH_P2WPKH => MultisigWalletType::P2SH_P2WSH,
                WalletType::P2WPKH => MultisigWalletType::P2WSH
            })
        }

        //Else return an error
        Err(HDWError::BadKey())
    }

    /**
        Given a vec of extended keys, this function will return the Network
        that the extended key is used for only if all the extended keys use the same network.
    */
    pub fn network_from_xkeys(keys: &Vec<&str>) -> Result<Network, HDWError> {
        //Collect the network of each key
        let networks = keys.iter().map(|x| {
            WalletType::network_from_xkey(x).unwrap()
        }).collect::<Vec<Network>>();

        //Check if they are all the same
        if networks.iter().all(|n| *n == networks[0]) {
            return Ok(networks[0])
        }

        //Return error if not
        Err(HDWError::BadKey())
    }
}


pub struct MultisigHDWallet {
    //List of the shared public keys.
    //For BIP-45 this is the purpose level keys and are sorted in lexicographical order
    //For BIP-48 this is the script-type level keys
    shared_public_keys: Vec<Xpub>,  
    
    //The required amount of keys for unlocking an m-of-n multisig script
    //Used in script creation
    quorum: u8,

    //The type of wallet
    //Used to determine what derivation scheme to use and the script-type field
    //for BIP-48 wallets
    wallet_type: MultisigWalletType,

    //The network the wallet is used for.
    //For BIP-45 this is used only during address creation
    //For BIP-48 this is used in the coin-type level and address creation.
    network: Network,

    //The BIP-48 account number
    //Not required for legacy P2SH wallets
    account: Option<u32>
}

impl MultisigHDWallet {
    /**
        Create a derivation path to the shared keys level.
        
        For BIP-45, this is the purpose level.
        For BIP-48, this is the script-type level.
    */
    fn path_to_shared_keys(
        wallet_type: MultisigWalletType,
        network: Network,
        account_index: Option<u32>
    ) -> Result<Path, HDWError> {
        //Creating the path to the shared level.
        //Purpose for BIP-45 and script-type for BIP-48
        let path: Path = match wallet_type {
            MultisigWalletType::P2SH => Path::from_str("m/45'")?,

            MultisigWalletType::P2WSH | MultisigWalletType::P2SH_P2WSH => {
                //Return the path with:

                //purpose
                let mut path = Path::from_str("m/48'")?; 
                
                //coin-type
                path.children.push(ChildOptions::Hardened(match network { 
                    Network::Bitcoin => 0,
                    Network::Testnet => 1
                }));

                //account index
                path.children.push(ChildOptions::Hardened(account_index.unwrap_or(0)));

                //script-type
                path.children.push(ChildOptions::Hardened(wallet_type as u32)); 

                path
            }
        };

        Ok(path)
    }

    /**
        Sorts a given list of extended public keys.
        
        This is used when creating a BIP-45 hd wallet to determine the 
        cosigner indexes
    */
    fn sort_keys(keys: &mut Vec<Xpub>) {
        keys.sort_by(|a, b| {
            a.get_pub().hex().cmp(&b.get_pub().hex())
        });
    }
    
    /**
        Create multisig wallet from a list of mnemonics
    */
    pub fn from_mnemonics(
        mnemonics: &Vec<Mnemonic>,
        quorum: u8,
        wallet_type: MultisigWalletType,
        network: Network,
        account_index: Option<u32>
    ) -> Result<Self, HDWError> {
        let path: Path = Self::path_to_shared_keys(wallet_type, network, account_index)?;
        let mut shared_public_keys = mnemonics.iter().map(|x| {
            Xprv::from_mnemonic(x).unwrap()
                .derive_from_path(&path).unwrap()
                .get_xpub()
        }).collect::<Vec<Xpub>>();
        
        //If BIP-45 is used, sort the shared keys in lexicographical order.
        if wallet_type == MultisigWalletType::P2SH { Self::sort_keys(&mut shared_public_keys) }

        Ok(
            Self {
                shared_public_keys,
                quorum,
                wallet_type,
                network,
                account: account_index
            }
        )
    }

    /**
        Create multisig wallet from a list of master private keys
    */
    pub fn from_master_privates(
        keys: &Vec<&str>,
        quorum: u8,
        account_index: Option<u32>
    ) -> Result<Self, HDWError> {
        //Derive the wallet type and network from given keys
        let wallet_type = MultisigWalletType::from_xkeys(keys)?;
        let network = MultisigWalletType::network_from_xkeys(keys)?;

        //Get the path to shared keys from wallet type, network and account index if given one.
        //Then for each key derive child keys to the shared path.
        let path: Path = Self::path_to_shared_keys(wallet_type, network, account_index)?;
        let mut shared_public_keys: Vec<Xpub> = keys.iter().map(|x| {
            Xprv::from_str(x).unwrap()
                .derive_from_path(&path).unwrap()
                .get_xpub()
        }).collect::<Vec<Xpub>>();

        //If BIP-45 is used, sort the shared keys in lexicographical order.
        if wallet_type == MultisigWalletType::P2SH { Self::sort_keys(&mut shared_public_keys) }

        //Return self
        Ok(
            Self {
                shared_public_keys,
                quorum,
                wallet_type,
                network,
                account: account_index
            }
        )
    }

    /**
        Create multisig wallet from a list of share level public keys
    */
    pub fn from_account_publics(keys: &Vec<&str>, quorum: u8, account_index: Option<u32>) -> Result<Self, HDWError> {
        //Derive the wallet type and network from given keys
        let wallet_type = MultisigWalletType::from_xkeys(keys)?;
        let network = MultisigWalletType::network_from_xkeys(keys)?;
        
        //Convert each key string to a Xpub struct
        let mut shared_public_keys = keys.iter().map(|x| {
            Xpub::from_str(x).unwrap()
        }).collect::<Vec<Xpub>>();

        //If BIP-45 is used, sort the shared keys in lexicographical order.
        if wallet_type == MultisigWalletType::P2SH { Self::sort_keys(&mut shared_public_keys) }

        //Return self
        Ok(
            Self {
                shared_public_keys,
                quorum,
                wallet_type,
                network,
                account: account_index
            }
        )
    }

    /*
        Returns the derivation path needed to get from the shared keys to the address keys.
    */
    fn address_path_from_shared(&self, change: bool, address_index: u32, cosigner_index: Option<u8>,) -> Path {
        let mut path = Path::empty();
        
        //If using BIP-45, push the cosigner index
        if self.wallet_type == MultisigWalletType::P2SH {
            path.children.push(ChildOptions::Normal(cosigner_index.unwrap_or(0) as u32));
            
        }

        //Push the change and address values
        path.children.push(ChildOptions::Normal(change as u32));
        path.children.push(ChildOptions::Normal(address_index));

        path
    }

    /**
        Returns the total number of keys in the multisig setup
    */
    pub fn total(&self) -> u8 {
        self.shared_public_keys.len() as u8
    }

    //Unlocks one of the keys in the multisig setup
    fn unlock(&self, unlocker: &Unlocker) -> Result<(), HDWError> {
        //Derive the share level key from the unlocker
        let shared_key = unlocker.master_private_key
                            .derive_from_path(
                                &Self::path_to_shared_keys(self.wallet_type, self.network, self.account)?
                            )?;
        
        //For each stored key, check if the derived key is equal.
        //If it is equal, return
        for i in 0..self.shared_public_keys.len() {
            if shared_key.key::<33>() == self.shared_public_keys[i].key::<33>() {
                return Ok(())
            }
        }

        //Else return an error
        Err(HDWError::BadKey())
    }

    pub fn redeem_script_at(
        &self,
        change: bool,
        address_index: u32,
        cosigner_index: Option<u8>
    ) -> Result<Script, HDWError> {
        // //Get the derivation path from the shared level to address level
        // let path_to_address = self.address_path_from_shared(change, address_index, cosigner_index);
        
        // //Create a vec of public keys by iterating over each stored key and deriving the requried child.
        // let mut keys: Vec<PubKey> = vec![];
        // self.shared_public_keys.iter().for_each(|k| {
        //     keys.push(k.derive_from_path(&path_to_address).unwrap().get_pub())
        // });

        let keys = self.address_public_keys(change, address_index, cosigner_index, true);

        //Create a multisig script from the quorum and key vector
        match Script::multisig(self.quorum, &keys) {
            Ok(script) => return Ok(script),
            Err(_) => return Err(HDWError::BadKey())
        }
    }
    
    pub fn address_at(
        &self,
        change: bool,
        address_index: u32,
        cosigner_index: Option<u8>
    ) -> Result<String, HDWError>
    where Self: Sized {
        //Get the addresses at the given path and up count times.
        let redeem_script: Script = self.redeem_script_at(change, address_index, cosigner_index)?;

        //Get the address depending on the wallet type
        match self.wallet_type {
            MultisigWalletType::P2SH => Ok(Address::P2SH(redeem_script, self.network).to_string().unwrap()),
            MultisigWalletType::P2WSH => Ok(Address::P2WSH(redeem_script, self.network).to_string().unwrap()),
            MultisigWalletType::P2SH_P2WSH => {
                let wrapped_script = Script::p2sh_p2wsh(&redeem_script);
                Ok(Address::P2SH(wrapped_script, self.network).to_string().unwrap())
            },
        }
    }

    /**
        Check if a master private key in an unlocker matches one of the shared public keys in 
        the wallet. 

        If yes, return the master private key
    */
    pub fn master_private_key(&self, unlocker: &Unlocker) -> Result<Xprv, HDWError> {
        self.unlock(unlocker)?;

        Ok(unlocker.master_private_key.clone())
    }

    /**
        Check if a master private key in an unlocker matches one of the shared public keys in 
        the wallet. 

        If match, return the corresponding share level private key
    */
    pub fn shared_private_key(&self, unlocker: &Unlocker) -> Result<Xprv, HDWError> {
        self.unlock(unlocker)?;

        Ok(
            unlocker.master_private_key.derive_from_path(
                &Self::path_to_shared_keys(self.wallet_type, self.network, self.account)?
            )?
        )
    }

    /**
        Check if a master private key in an unlocker matches one of the shared public keys in 
        the wallet. 

        If match, return the corresponding address level private key
    */
    pub fn address_private_key(&self, change: bool, address_index: u32, cosigner_index: Option<u8>, unlocker: &Unlocker) -> Result<PrivKey, HDWError> {
        self.unlock(unlocker)?;
        
        //Create the path from master to address
        let mut path = Self::path_to_shared_keys(self.wallet_type, self.network, self.account)?;
        path.children.append(&mut Self::address_path_from_shared(&self, change, address_index, cosigner_index).children);

        //Return the private key at the address
        Ok(
            unlocker.master_private_key.derive_from_path(&path)?.get_prv()
        )
    }

    /**
        Return the public keys at a given address path
    */
    pub fn address_public_keys(
        &self, change: bool,
        address_index: u32,
        cosigner_index: Option<u8>,
        sort: bool
    ) -> Vec<PubKey> {
        //Get the derivation path from the shared level to address level
        let path_to_address = self.address_path_from_shared(change, address_index, cosigner_index);
        
        //Create a vec of public keys by iterating over each stored key and deriving the requried child.
        let mut extended_keys = self.shared_public_keys.clone();
        if sort { Self::sort_keys(&mut extended_keys) }

        let mut keys: Vec<PubKey> = vec![];
        extended_keys.iter().for_each(|k| {
            keys.push(k.derive_from_path(&path_to_address).unwrap().get_pub())
        });

        

        keys
    }
}