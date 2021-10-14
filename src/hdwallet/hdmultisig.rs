/*
    Module implementing Multisig HD Wallet data structures

    Todo:.
        - HD Multisig wallet builder, address generator and key extracting should be working (no unit tests)
        - Builder to track path used to derive each shared key and return error upon build if
          any of the paths use a different path from the others.
        - The pathing trait could be used for Singlesig HDWallets as well.
        - The pathing trait could take in custom paths from master (with unlocker)
        
            ****************
            ** UNIT TESTS **
            ****************
          
*/

use crate::{
    address::Address,
    bip39::Mnemonic,
    key::{
        PrivKey, PubKey
    },
    script::Script,
    util::Network
};
use super::{
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

/**
    Builder struct to make creating HD Multisig Wallets easier.
    Can only create standard BIP-45 or BIP-48 wallets for the time being.

    When using this struct, it is recommended that if any values are going
    to be changed from the default recommended values, that it is done before
    adding signers. 

    Issues can arise if signers are added and then default values are changed,
    since the signers shared key is stored using the default value before values
    change and the new shared keys cannot be reevaluated upon value change.
    
    This issue can be averted by tracking the path used to derive the shard keys
    and making sure they are all the same.
*/
pub struct MultisigHDWalletBuilder {
    pub wallet_type: Option<MultisigWalletType>, //Defaults to P2WSH
    pub quorum: Option<u8>,                      //Required
    pub network: Option<Network>,                //Defaults to Bitcoin
    pub account_index: Option<u32>,              //Defaults to 0
    pub signers: Vec<Xpub> //Track path here     //At least 1 signer required
}

/**
    Trait that returns path for standard multisig derivation paths
*/ 
trait MultisigStandardPathing {
    fn to_shared_from_master(
        wallet_type: MultisigWalletType,
        network: Network,
        account_index: u32
    ) -> Path{
        //Creating the path to the shared level.
        //Purpose for BIP-45 and script-type for BIP-48
        match wallet_type {
            //BPI-45 shared level is the purpose level
            MultisigWalletType::P2SH => Path::from_str("m/45'").unwrap(),

            //BIP-48 shared level is the script-type level
            MultisigWalletType::P2WSH | MultisigWalletType::P2SH_P2WSH => {
                //Return the path with:

                //purpose
                let mut path = Path::from_str("m/48'").unwrap(); 
                
                //coin-type
                path.children.push(ChildOptions::Hardened(match network { 
                    Network::Bitcoin => 0,
                    Network::Testnet => 1
                }));

                //account index
                path.children.push(ChildOptions::Hardened(account_index));

                //script-type
                path.children.push(ChildOptions::Hardened(wallet_type as u32)); 

                path
            }
        }
    }

    fn to_address_from_master(
        wallet_type: MultisigWalletType,
        network: Network,
        account_index: u32,
        cosigner_index: Option<u8>,
        change: bool,
        address_index: u32
    ) -> Result<Path, HDWError> {
        let mut path = Self::to_shared_from_master(wallet_type, network, account_index);
        match cosigner_index {
            Some(x) => path.children.push(ChildOptions::Normal(x as u32)),
            None => { /* Don't add cosigner index to path if not presented */ }
        }
        path.children.push(ChildOptions::Normal(change as u32));
        path.children.push(ChildOptions::Normal(address_index));

        Ok(path)
    }

    fn to_address_from_shared(
        cosigner_index: Option<u8>,
        change: bool,
        address_index: u32
    ) -> Path {
        let mut path = Path::empty();
        
        //Add the cosigner index to the path if it is given
        match cosigner_index {
            Some(x) => path.children.push(ChildOptions::Normal(x as u32)),
            None => { /*Dont add cosigner index to path if not presented*/ }
        }
        path.children.push(ChildOptions::Normal(change as u32));
        path.children.push(ChildOptions::Normal(address_index));

        path
    }
}

impl MultisigStandardPathing for MultisigHDWalletBuilder { }
impl MultisigHDWalletBuilder {
    //Return a new instance of the builder with empty values
    pub fn new() -> Self {
        Self {
            wallet_type: None,
            quorum: None,
            network: None,
            account_index: None,
            signers: vec![]
        }
    }

    //Set the wallet type in the builder
    pub fn set_type(&mut self, wallet_type: MultisigWalletType) {
        self.wallet_type = Some(wallet_type)
    }

    //Set the network in the builder
    pub fn set_network(&mut self, network: Network) {
        self.network = Some(network)
    }

    //Set the quorum of the multisig setup. This is a required field
    pub fn set_quorum(&mut self, quorum: u8) {
        self.quorum = Some(quorum)
    }

    //Set the account index. Only relevant for BIP-48 wallets.
    pub fn set_account_index(&mut self, account_index: u32) {
        self.account_index = Some(account_index)
    }

    /**
        Extracts values in the builder for wallet type, network and account index and if 
        none are set uses default values. 
    */
    fn extract_or_default(&self) -> (MultisigWalletType, Network, u32) {
        let wallet_type = self.wallet_type.unwrap_or(MultisigWalletType::P2WSH);
        let network = self.network.unwrap_or(Network::Bitcoin);
        let account_index = self.account_index.unwrap_or(0);

        (wallet_type, network, account_index)
    }

    //Add a new signer from Mnemonic
    pub fn add_signer_from_mnemonic(&mut self, mnemonic: &Mnemonic) {    
        //If values are unset, use default values
        let (wallet_type, network, account_index) = self.extract_or_default();

        //Derive the share level key from the given mnemonic
        let share_path: Path = Self::to_shared_from_master(wallet_type, network, account_index);
        let signer_master_key = Xprv::from_mnemonic(mnemonic).unwrap();
        let signer_shared_key = signer_master_key.derive_from_path(&share_path).unwrap().get_xpub();
        
        self.signers.push(signer_shared_key);
    }

    //Add a new signer from Xprv key
    pub fn add_signer_from_xprv(&mut self, signer_master_key: &Xprv) {
        //If values are unset, use default values
        let (wallet_type, network, account_index) = self.extract_or_default();

        //Derive the share level key from the provided Xprv key
        let share_path: Path = Self::to_shared_from_master(wallet_type, network, account_index);
        let signer_shared_key = signer_master_key.derive_from_path(&share_path).unwrap().get_xpub();
        
        self.signers.push(signer_shared_key);
    }

    //Add a new signer from xpub shared key
    pub fn add_signer_from_xpub(&mut self, shared_key: &Xpub) {
        self.signers.push(shared_key.clone())
    }

    //Build the wallet
    //In here, when path tracking is implemented, the paths will need to be checked if they are all the same.
    pub fn build(&self) -> Result<MultisigHDWallet, HDWError> {
        //Fields that are required to be set manually
        if self.signers.len() == 0 { return Err(HDWError::MissingFields) }
        let quorum = match self.quorum {
            Some(x) => x,
            None => return Err(HDWError::MissingFields)
        };

        //Fields that dont need to be set manually and have a default value
        let (wallet_type, network, account_index) = self.extract_or_default();
        

        //Sort the keys in lexicographical order of PubKey
        let mut shared_public_keys = self.signers.clone();
        shared_public_keys.sort_by(|a, b| {
            a.get_pub().hex().cmp(&b.get_pub().hex())
        });

        //Create and return the wallet
        let wallet = MultisigHDWallet {
            shared_public_keys,
            quorum,
            wallet_type,
            network,
            account_index: Some(account_index)
        };
        Ok(wallet)
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
    account_index: Option<u32>
}

impl MultisigStandardPathing for MultisigHDWallet { }
impl MultisigHDWallet {

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
        let path: Path = Self::to_shared_from_master(wallet_type, network, account_index.unwrap());//Self::path_to_shared_keys(wallet_type, network, account_index)?;
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
                account_index
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
        let path: Path = Self::to_shared_from_master(wallet_type, network, account_index.unwrap());//Self::path_to_shared_keys(wallet_type, network, account_index)?;
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
                account_index
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
                account_index
            }
        )
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
                                &Self::to_shared_from_master(self.wallet_type, self.network, self.account_index.unwrap())//&Self::path_to_shared_keys(self.wallet_type, self.network, self.account_index)?
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
        cosigner_index: Option<u8>,
        change: bool,
        address_index: u32
    ) -> Result<Script, HDWError> {
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
        let redeem_script: Script = self.redeem_script_at(cosigner_index, change, address_index)?;

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
                &Self::to_shared_from_master(self.wallet_type, self.network, self.account_index.unwrap())//&Self::path_to_shared_keys(self.wallet_type, self.network, self.account_index)?
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
        let mut path = Self::to_shared_from_master(self.wallet_type, self.network, self.account_index.unwrap());//Self::path_to_shared_keys(self.wallet_type, self.network, self.account_index)?;
        path.children.append(&mut Self::to_address_from_shared(cosigner_index, change, address_index).children/*&mut Self::address_path_from_shared(&self, change, address_index, cosigner_index).children*/);

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
        let path_to_address = Self::to_address_from_shared(cosigner_index, change, address_index);//self.address_path_from_shared(change, address_index, cosigner_index);
        
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