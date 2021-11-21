/*
    Module implementing Multisig HD Wallet data structures

    Todo:
        - Expoting of shared keys using SLIP-0132 version prefixes.
            - Should just be a matter of matching network and wallet type and selecting appropriate
              SLIP version prefix to pass into extended key serialization method.
        
        - Better unlocker that can take in multiple keys at a time.
            - Only return the requested values of correct keys
            - How to signify that a wrong key was given? (Index of wrong key etc...)
        
        - Custom path wallets unit tests
          
*/

use crate::{
    address::Address,
    bip39::Mnemonic,
    key::{
        PrivKey, PubKey
    },
    script::RedeemScript,
    util::{
        Network,
        try_into, as_u32_be
    },
    encoding::{
        base58::Base58,
        version_prefix::VersionPrefix,
        version_prefix::ToVersionPrefix
    }
};
use super::{
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
    pub fn from_xkeys(key: &str) -> Result<Self, HDWError> {
        let bytes = match Base58::decode(key) {
            Ok(x) => x,
            Err(_) => return Err(HDWError::BadKey())
        };

        if bytes.len() < 4 { return Err(HDWError::BadKey()) }
        let version: u32 = as_u32_be(&try_into(bytes[0..4].to_vec()));
        match VersionPrefix::from_int(version) {
            Ok(x) => match x {
                //P2PKH
                VersionPrefix::Xprv |
                VersionPrefix::Xpub |
                VersionPrefix::Tprv |
                VersionPrefix::Tpub => Ok(MultisigWalletType::P2SH),
                //Nested Segwit
                VersionPrefix::Yprv |
                VersionPrefix::Ypub |
                VersionPrefix::Uprv |
                VersionPrefix::Upub |
                VersionPrefix::SLIP132Ypub |
                VersionPrefix::SLIP132Upub => Ok(MultisigWalletType::P2SH_P2WSH),
                
                //Native Segwit
                VersionPrefix::Zprv |
                VersionPrefix::Zpub |
                VersionPrefix::Vprv |
                VersionPrefix::Vpub |
                VersionPrefix::SLIP132Zpub |
                VersionPrefix::SLIP132Vpub => Ok(MultisigWalletType::P2WSH),
                
                _ => return Err(HDWError::BadKey())
            },
            
            //Return an error if not valid
            _ => return Err(HDWError::BadKey())
        }
    }
}

impl ToVersionPrefix for MultisigWalletType {
    fn public_version_prefix(&self, network: Network) -> VersionPrefix {
        match &self {
            MultisigWalletType::P2SH => match network {
                Network::Bitcoin => VersionPrefix::Xpub,
                Network::Testnet => VersionPrefix::Tpub
            },
            MultisigWalletType::P2SH_P2WSH => match network {
                Network::Bitcoin => VersionPrefix::Ypub,
                Network::Testnet => VersionPrefix::Upub
            },
            MultisigWalletType::P2WSH => match network {
                Network::Bitcoin => VersionPrefix::Zpub,
                Network::Testnet => VersionPrefix::Vpub
            },
        }
    }

    fn private_version_prefix(&self, network: Network) -> VersionPrefix {
        match &self {
            MultisigWalletType::P2SH => match network {
                Network::Bitcoin => VersionPrefix::Xprv,
                Network::Testnet => VersionPrefix::Tprv
            },
            MultisigWalletType::P2SH_P2WSH => match network {
                Network::Bitcoin => VersionPrefix::Yprv,
                Network::Testnet => VersionPrefix::Uprv
            },
            MultisigWalletType::P2WSH => match network {
                Network::Bitcoin => VersionPrefix::Zprv,
                Network::Testnet => VersionPrefix::Vprv
            },
        }
    }

    fn get_version_prefix(&self, network: Network) -> (VersionPrefix, VersionPrefix) {
        match &self {
            MultisigWalletType::P2SH => match network {
                Network::Bitcoin => (VersionPrefix::Xpub, VersionPrefix::Xprv),
                Network::Testnet => (VersionPrefix::Tpub, VersionPrefix::Tprv)
            },
            MultisigWalletType::P2SH_P2WSH => match network {
                Network::Bitcoin => (VersionPrefix::Ypub, VersionPrefix::Yprv),
                Network::Testnet => (VersionPrefix::Upub, VersionPrefix::Uprv)
            },
            MultisigWalletType::P2WSH => match network {
                Network::Bitcoin => (VersionPrefix::Zpub, VersionPrefix::Zprv),
                Network::Testnet => (VersionPrefix::Vpub, VersionPrefix::Vprv)
            }
        }
    }
}

/**
    Builder struct to make creating HD Multisig Wallets easier.
    Can only create standard BIP-45 or BIP-48 wallets for the time being.
*/
const MAX_KEYS_FOR_SETUP: u8 = 15;
pub struct MultisigHDWalletBuilder<'builder> {
    wallet_type: Option<MultisigWalletType>, //Defaults to P2WSH
    quorum: Option<u8>,                      //Required
    network: Option<Network>,                //Defaults to Bitcoin
    account_index: Option<u32>,              //Defaults to 0
    derivation: Option<&'builder str>,       //Defaults to either BIP-45 or BIP-48

    master_signer_keys: Vec<Xprv>,
    shared_signer_keys:  Vec<Xpub>,
}

/**
    Trait that returns path for standard multisig derivation paths
*/ 
trait MultisigStandardPathing {
    fn to_shared_from_master(
        wallet_type: MultisigWalletType,
        network: Network,
        account_index: u32 //or cosigner_index
    ) -> Path{
        //Creating the path to the shared level.
        //Purpose for BIP-45 and script-type for BIP-48
        match wallet_type {
            //BPI-45 shared level is the cosigner_index level.
            //Electrum and Bluewallet use m/45'/0 so this library will use the same share level but with a 
            //customizable cosigned index. 
            MultisigWalletType::P2SH =>  { 
                let mut path = Path::from_str("m/45'").unwrap();
                path.add_level(ChildOptions::Normal(account_index)); //Cosigner Index

                path
            },

            //BIP-48 shared level is the script-type level
            MultisigWalletType::P2WSH | MultisigWalletType::P2SH_P2WSH => {
                //Return the path with:

                //purpose
                let mut path = Path::from_str("m/48'").unwrap(); 
                
                //coin-type
                path.add_level(ChildOptions::Hardened(match network { 
                    Network::Bitcoin => 0,
                    Network::Testnet => 1
                }));

                //account index
                path.add_level(ChildOptions::Hardened(account_index));

                //script-type
                path.add_level(ChildOptions::Hardened(wallet_type as u32)); 

                path
            }
        }
    }

    fn to_address_from_master(
        wallet_type: MultisigWalletType,
        network: Network,
        account_index: u32,
        change: bool,
        address_index: u32
    ) -> Path {
        let mut path = Self::to_shared_from_master(wallet_type, network, account_index);
        path.append(&Self::to_address_from_shared(change, address_index));

        path
    }

    //Regardless of whether a custom path is being used, this method will add the 
    //change index and address index to the path being used to derive the address.
    fn to_address_from_shared(
        change: bool,
        address_index: u32
    ) -> Path {
        let mut path = Path::empty();
        path.add_level(ChildOptions::Normal(change as u32));
        path.add_level(ChildOptions::Normal(address_index));

        path
    }
}


impl<'builder> MultisigStandardPathing for MultisigHDWalletBuilder<'builder> { }
impl<'builder> MultisigHDWalletBuilder<'builder> {
    //Return a new instance of the builder with empty values
    pub fn new() -> Self {
        Self {
            wallet_type: None,
            quorum: None,
            network: None,
            account_index: None,
            derivation: None,

            master_signer_keys: vec![],
            shared_signer_keys: vec![],
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
    //This is the cosigner index for BIP-45 wallets.
    //For example, if a legacy multisig wallet using cosigner_index #2 is to be created,
    //set the cosigner index using this method.
    pub fn set_account_index(&mut self, account_index: u32) {
        self.account_index = Some(account_index)
    }

    //If a custom derivation is used, set it here
    pub fn set_custom_derivation(&mut self, path: &'builder str) {
        self.derivation = Some(path);
    }

    //Add a new signer from Mnemonic
    pub fn add_signer_from_mnemonic(&mut self, mnemonic: &Mnemonic) -> Result<(), HDWError> {    
        let signer_master_key = Xprv::from_mnemonic(mnemonic)?;

        //No data to extract from mnemonic. Only store master key
        self.master_signer_keys.push(signer_master_key);

        Ok(())
    }

    //Add a new signer from root Xprv key
    pub fn add_signer_from_xprv(&mut self, signer_master_key: &str) -> Result<(), HDWError> {
        //Store the inferred wallet type and network if they are the same as the others.
        self.add_inferred_type(signer_master_key)?;
        
        
        //Determine the key type and if it is a SLIP key, store in the shared list.
        //If it is a not a slip key but also not invalid, store in master list.
        let bytes = match Base58::decode(signer_master_key) {
            Ok(x) => x,
            Err(_) => return Err(HDWError::BadKey())
        };

        let version: u32 = as_u32_be(&try_into(bytes[0..4].to_vec()));
        match VersionPrefix::from_int(version) {
            Ok(x) => match x {
                //Non SLIP key
                VersionPrefix::Xprv |
                VersionPrefix::Xpub |
                VersionPrefix::Tprv |
                VersionPrefix::Tpub |
                VersionPrefix::Yprv |
                VersionPrefix::Ypub |
                VersionPrefix::Uprv |
                VersionPrefix::Upub |
                VersionPrefix::Zprv |
                VersionPrefix::Zpub |
                VersionPrefix::Vprv |
                VersionPrefix::Vpub  => { 
                    //Store the key as a master key
                    let key: Xprv = Xprv::from_str(signer_master_key)?;
                    self.master_signer_keys.push(key);
                },

                //SLIP Key
                VersionPrefix::SLIP132Yprv |
                VersionPrefix::SLIP132Zprv |
                VersionPrefix::SLIP132Uprv |
                VersionPrefix::SLIP132Vprv => {
                    //Get the corresponding xpub and store as shared
                    let key: Xpub = Xprv::from_str(signer_master_key)?.get_xpub();
                    self.shared_signer_keys.push(key);
                },
 
                //Invalid version prefix
                _ => return Err(HDWError::BadKey())
            },
            
            //Cannot detect version prefix
            _ => return Err(HDWError::BadKey())
        }

        Ok(())
    }

    //Add a new signer from xpub shared key
    //NEEDS TO ACCEPT SLIP-0132 Multisig public keys
    pub fn add_signer_from_xpub(&mut self, shared_key: &str)-> Result<(), HDWError> {
        //Store the inferred wallet type and network if they are the same as the others.
        self.add_inferred_type(shared_key)?;
        
        //Store the key
        let key: Xpub = Xpub::from_str(shared_key)?;
        self.shared_signer_keys.push(key);

        Ok(())
    }

    //This method runs everytime a signer is added via xprv or xpub key.
    //It takes in the key and extracts wallet type and network info from it and adds it to the list of
    //inferred wallet data if it matches with the previous element in the list.
    fn add_inferred_type(&mut self, key: &str) -> Result<(), HDWError> {
        //Extract the wallet meta data from the key
        let wallet_type: MultisigWalletType = MultisigWalletType::from_xkeys(key)?;
        let network: Network = match Network::from_xkey(key) {
            Ok(x) => x,
            Err(_) => return Err(HDWError::BadKey())
        };
        
        //If there is a mismatch between inferred and specified wallet type or network, 
        //return an error.
        if self.wallet_type.is_some() && self.wallet_type.unwrap() != wallet_type ||
           self.network.is_some() && self.network.unwrap() != network 
        {
            return Err(HDWError::TypeDiscrepancy)
        }
        
        
        //If there is no mismatches or no values are set
        self.wallet_type = Some(wallet_type);
        self.network = Some(network);
        Ok(())
    }

    /**
        Extracts values in the builder for wallet type, network and account index and if 
        none are set uses default values. 
    */
    fn extract_or_default(&self) -> (MultisigWalletType, Network, u32) {
        //Needs to take into account inferred data as well.
        
        let wallet_type = self.wallet_type.unwrap_or(MultisigWalletType::P2WSH);
        let network = self.network.unwrap_or(Network::Bitcoin);
        let account_index = self.account_index.unwrap_or(0);

        (wallet_type, network, account_index)
    }

    //Build the wallet
    //In here, when path tracking is implemented, the paths will need to be checked if they are all the same.
    pub fn build(&self) -> Result<MultisigHDWallet, HDWError> {
        //Get the amount of keys from the sum of master keys and shared keys provided
        let signer_count: u8 = self.shared_signer_keys.len() as u8 + self.master_signer_keys.len() as u8;
        if signer_count > MAX_KEYS_FOR_SETUP { return Err(HDWError::IndexTooLarge(signer_count as u32)) }
        
        //If the amount of keys is 0, fail
        if signer_count == 0 { return Err(HDWError::MissingFields) }
        
        //Extract the quorum, if nothing is provided or the quorum is zero, fail.
        let quorum = match self.quorum {
            Some(x) => {
                if x == 0 { return Err(HDWError::BadQuorum(x)) }
                if x > signer_count as u8 { return Err(HDWError::BadQuorum(x)) }

                x
            },
            None => return Err(HDWError::MissingFields)
        };


        //Use the data stored in the builder or result to defaults if nothing is set
        let (wallet_type, network, account_index) = self.extract_or_default(); 
        

        //Merge all the master signer keys and shared signer keys into a single vector of shared ex-pub keys.
        //Do this by deriving master keys into share level keys according to wallet type, network and account index.
        let path_to_shared = match self.derivation {
            //If a custom path if given, use it.
            Some(x) => Path::from_str(x)?,

            //Else, use a standard path for BIP-48 or BIP-45 depending on wallet type etc...
            None => Self::to_shared_from_master(wallet_type, network, account_index)
        };

        let mut shared_public_keys = self.shared_signer_keys.clone();
        shared_public_keys.append(
            &mut self.master_signer_keys.iter().map(|x| {
                x.derive_from_path(&path_to_shared)
                .unwrap()
                .get_xpub()
            }).collect::<Vec<Xpub>>()
        );
        
        //Sort the shared keys in lexicographical order of PubKey
        //Disabled since its not required
        //
        //shared_public_keys.sort();
        //

        //Create and return the wallet
        let wallet = MultisigHDWallet {
            shared_public_keys,
            quorum,
            wallet_type,
            network,
            //account_index: Some(account_index),
            derivation: path_to_shared
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

    //The path from a master key to a shared key
    //This can either be a standard path or a custom path
    derivation: Path
}

impl MultisigStandardPathing for MultisigHDWallet { }
impl MultisigHDWallet {

    /**
        Returns the total number of keys in the multisig setup
    */
    pub fn total(&self) -> u8 {
        self.shared_public_keys.len() as u8
    }

    //Unlocks one of the keys in the multisig setup
    fn unlock(&self, unlocker: &Unlocker) -> Result<(), HDWError> {
        //Derive the share level key from the unlocker
        let shared_key: Xpub = unlocker.master_private_key
                            .derive_from_path(
                                &self.derivation
                            )?.get_xpub();
        
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

    //Creates the redeem script at a given standard path
    pub fn redeem_script_at(
        &self,
        change: bool,
        address_index: u32
    ) -> Result<RedeemScript, HDWError> {
        let keys = self.address_public_keys(change, address_index, true);

        //Create a multisig script from the quorum and key vector
        match RedeemScript::multisig(self.quorum, &keys) {
            Ok(script) => return Ok(script),
            Err(_) => return Err(HDWError::BadKey())
        }
    }
    
    //Generates an address at a given standard path
    pub fn address_at(
        &self,
        change: bool,
        address_index: u32
    ) -> Result<String, HDWError>
    where Self: Sized {
        //Get the addresses at the given path and up count times.
        let redeem_script: RedeemScript = self.redeem_script_at(change, address_index)?;

        //Get the address depending on the wallet type
        match self.wallet_type {
            MultisigWalletType::P2SH => Ok(Address::P2SH(redeem_script, self.network).to_string().unwrap()),
            MultisigWalletType::P2WSH => Ok(Address::P2WSH(redeem_script, self.network).to_string().unwrap()),
            MultisigWalletType::P2SH_P2WSH => {
                let wrapped_script = RedeemScript::p2wsh(&redeem_script);
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

        Ok(unlocker.master_private_key)
    }

    /**
        Check if a master private key in an unlocker matches one of the shared public keys in 
        the wallet. 

        If match, return the corresponding share level private key
    */
    pub fn shared_private_key(&self, unlocker: &Unlocker) -> Result<Xprv, HDWError> {
        self.unlock(unlocker)?;

        Ok(
            unlocker.master_private_key.derive_from_path( &self.derivation )?
        )
    }

    /**
        Check if a master private key in an unlocker matches one of the shared public keys in 
        the wallet. 

        If match, return the corresponding address level private key
    */
    pub fn address_private_key(&self, change: bool, address_index: u32, unlocker: &Unlocker) -> Result<PrivKey, HDWError> {
        self.unlock(unlocker)?;
        
        //Create the path from master to address
        let mut path = self.derivation.clone();
        //path.children.append(&mut Self::to_address_from_shared(change, address_index).children);
        path.append(&Self::to_address_from_shared(change, address_index));

        //Return the private key at the address
        Ok(
            unlocker.master_private_key.derive_from_path(&path)?.get_prv()
        )
    }

    /**
        Return the public keys at a given address path
    */
    pub fn address_public_keys(
        &self, 
        change: bool,
        address_index: u32,
        sort: bool  //May not be required
    ) -> Vec<PubKey> {
        //Get the derivation path from the shared level to address level
        let path_to_address = Self::to_address_from_shared(change, address_index);

        //Create a vec of public keys by iterating over each stored key and deriving the requried child.
        let mut extended_keys = self.shared_public_keys.clone();
        if sort { extended_keys.sort() }

        let mut keys: Vec<PubKey> = vec![];
        extended_keys.iter().for_each(|k| {
            keys.push(k.derive_from_path(&path_to_address).unwrap().get_pub())
        });

        

        keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;

    #[test]
    fn good_segwit_multisig_wallet() -> Result<(), HDWError> {
        let mut wallets = vec![];
        wallets.push( segwit_from_mnemonics()? );
        wallets.push( segwit_from_master_keys()? );
        wallets.push( segwit_from_shared_keys_slip()? );
        wallets.push( segwit_from_shared_keys_nonslip()? );
        wallets.push( segwit_from_a_bit_of_everything()? );


        //Check addresses
        for wallet in wallets {
            assert_eq!(wallet.address_at(false, 0)?, "bc1q2amk0dcqqs2gqfa6ju2td2xx42zz93n80paztjueltjefjugyv0qh6dtdx");
            assert_eq!(wallet.address_at(true, 0)?, "bc1qcgsxne2nppzu38yshxmls4ayzje8k3xk48r592wvpuyzgfayayasweyn85");
        }
        

        Ok(())
    }

    //Test builder using mnemonics and setting data
    fn segwit_from_mnemonics() -> Result<MultisigHDWallet, HDWError> {
        //Create new builder instance
        let mut b = MultisigHDWalletBuilder::new();
        
        //Set wallet meta data
        //Not setting account index, network and wallet type here means it will resort to default values of
        // Account #0, P2WPSH, Bitcoin Mainnet
        b.set_quorum(2);

        //Set mnemonics
        let mnemonic_1 = Mnemonic::from_phrase("valid wife trash caution slide coach lift visual goose buzz off silly".to_string(), Language::English, "").unwrap();
        let mnemonic_2 = Mnemonic::from_phrase("salon cloth blossom below emotion buffalo bone dilemma dinosaur morning interest gentle".to_string(), Language::English, "").unwrap();
        let mnemonic_3 = Mnemonic::from_phrase("desert shock swift grant chronic invite gasp jelly round design sand liquid".to_string(), Language::English, "").unwrap();

        //Add signer mnemonics
        b.add_signer_from_mnemonic(&mnemonic_1)?;
        b.add_signer_from_mnemonic(&mnemonic_2)?;
        b.add_signer_from_mnemonic(&mnemonic_3)?;

        //Build and return
        Ok(b.build()?)
    }

    fn segwit_from_master_keys() -> Result<MultisigHDWallet, HDWError> {
        //Create new builder instance
        let mut b = MultisigHDWalletBuilder::new();
                
        //Set wallet meta data
        //Builder will infer wallet data from keys in this case
        b.set_quorum(2);

        //Set keys
        let key_1 = "zprvAWgYBBk7JR8Gk4wY9P7HRhWuGrexyfJtFavR1bQq3nSzQ1PV88MrKBprf4YyHjuFvrRXWA17oWnsAjGTVsAoDeuwYrjHJyrzrHbq8Psiwc8";
        let key_2 = "zprvAWgYBBk7JR8GjujFvUS7zsufLSWC97bCHNoNc6yRWTz58wK4qYTxt9ikudjKi4gp2te2dD7TMq5urUYwD2MUsyjf2CGKoK1y2QdXsndoR9i";
        let key_3 = "zprvAWgYBBk7JR8Gj3FRCtDjzdBp5AuDvj9zLH68u9ELqeFHfMtdou591BUFXCByUKk9nEgQcA6SwLG1qP4KrT5FvkY8xGj3RBB88sSECQrMdbP";
        
        //Add signer master keys
        b.add_signer_from_xprv(key_1)?;
        b.add_signer_from_xprv(key_2)?;
        b.add_signer_from_xprv(key_3)?;

        //Build and return
        Ok(b.build()?)
    }

    fn segwit_from_shared_keys_slip() -> Result<MultisigHDWallet, HDWError> {
        //Create new builder instance
        let mut b = MultisigHDWalletBuilder::new();
                        
        //Set wallet meta data
        //Builder will infer wallet data from keys in this case
        b.set_quorum(2);

        //Set keys
        let key_1 = "Zpub75j4VFKBPDvPLXWNZ6WqLvW6WJa2FYKVSKcqew31p35h3snWWDGSkQDmR9evjNcN5Me131afLP2ctT33e2J1vvsTVYdF5LfvsbeJsTwf1c4";
        let key_2 = "Zpub74uWsWvBmsLWQiF3KacCCCC57xdKs6rj4xqgc4tbzAUMAvCWHiTonoqMBT3JgXEdzc2GejGrBJvgTY74wircjqFg8eVu46F2H6czR5XcxCe";
        let key_3 = "Zpub75Y1tnRN4yddaM6GCqJfHWDoRN7ZoLhf38nEQwJk2x6HCpnHL515VRmV8PAhzPcv5VVCEXn5pjgp7f9eamLU5pkfvpLcnDXFKfo58PxmU9n";

        //Add signer master keys
        b.add_signer_from_xpub(key_1)?;
        b.add_signer_from_xpub(key_2)?;
        b.add_signer_from_xpub(key_3)?;

        //Build and return
        Ok(b.build()?)
    }

    fn segwit_from_shared_keys_nonslip() -> Result<MultisigHDWallet, HDWError> {
        //Create new builder instance
        let mut b = MultisigHDWalletBuilder::new();
                        
        //Set wallet meta data
        //Builder will infer wallet data from keys in this case
        b.set_quorum(2);

        //Set keys
        let key_1 = "zpub6tpyN1ajpGN1uxLzcS3rWrAHnWXm3Bdu83yAjfmUSGFHRhDbjotAfHMqcShTAwPTqta2ARaYTAe7mHRHLo94nSknf5WqfwCvysNSHaYvGue";
        let key_2 = "zpub6t1RkHBkCun8z95fNv9DN7rGQAb4ekB8khC1god4cPdwYjdbXK5XhgyRNk5q861jm8xHn9GjJ6YBLNVJeVhfbM91JBPVegn2PNM7q9U3B33";
        let key_3 = "zpub6tdvmYgvW25G9mvtGAqgTRszha5Jaz24is8ZVg3CfBFsaeDNZfcoQJuZKgDERxQ1r2RDMwmxwXJJzVXtHYBWwLe16MEDNp4FRwXCYYoMd4c";
        
        

        //Add signer master keys
        b.add_signer_from_xpub(key_1)?;
        b.add_signer_from_xpub(key_2)?;
        b.add_signer_from_xpub(key_3)?;

        //Build and return
        Ok(b.build()?)
    }

    fn segwit_from_a_bit_of_everything() -> Result<MultisigHDWallet, HDWError> {
        let mut b = MultisigHDWalletBuilder::new();
                        
        //Set wallet meta data
        //Builder will infer wallet data from keys in this case
        b.set_quorum(2);

        //Set keys
        let mnemonic_1 = Mnemonic::from_phrase("valid wife trash caution slide coach lift visual goose buzz off silly".to_string(), Language::English, "").unwrap();
        let key_2 = "zprvAWgYBBk7JR8GjujFvUS7zsufLSWC97bCHNoNc6yRWTz58wK4qYTxt9ikudjKi4gp2te2dD7TMq5urUYwD2MUsyjf2CGKoK1y2QdXsndoR9i";
        let key_3 = "zpub6tdvmYgvW25G9mvtGAqgTRszha5Jaz24is8ZVg3CfBFsaeDNZfcoQJuZKgDERxQ1r2RDMwmxwXJJzVXtHYBWwLe16MEDNp4FRwXCYYoMd4c";
    
        //Add signers
        b.add_signer_from_mnemonic(&mnemonic_1)?;
        b.add_signer_from_xprv(key_2)?;
        b.add_signer_from_xpub(key_3)?;

        //Build and return
        Ok(b.build()?)
    }

    #[test]
    fn good_nested_segwit_multisig_wallet() -> Result<(), HDWError> {
        let mut wallets = vec![];
        wallets.push( nested_segwit_from_mnemonics()? );
        wallets.push( nested_segwit_from_shared_keys_slip()? );
        wallets.push( nested_segwit_from_a_bit_of_everything()? );
        
        

        //Check addresses
        for wallet in wallets {
            assert_eq!(wallet.address_at(false, 0)?, "3KcsKbj1gTwH3yUw6JN7Et9nhGci8CxXvx");
            assert_eq!(wallet.address_at(true, 0)?, "36r5RrBPb67M7kjxMriXkskt4h9xVpTXsa");
        }
        

        Ok(())
    }

    //Test builder using mnemonics and setting data
    fn nested_segwit_from_mnemonics() -> Result<MultisigHDWallet, HDWError> {
        //Create new builder instance
        let mut b = MultisigHDWalletBuilder::new();
        
        //Set wallet meta data
        //Account #0, Nested segwit, Bitcoin Mainnet
        b.set_quorum(2);
        b.set_type(MultisigWalletType::P2SH_P2WSH);

        //Set mnemonics
        let mnemonic_1 = Mnemonic::from_phrase("valid wife trash caution slide coach lift visual goose buzz off silly".to_string(), Language::English, "").unwrap();
        let mnemonic_2 = Mnemonic::from_phrase("salon cloth blossom below emotion buffalo bone dilemma dinosaur morning interest gentle".to_string(), Language::English, "").unwrap();
        let mnemonic_3 = Mnemonic::from_phrase("desert shock swift grant chronic invite gasp jelly round design sand liquid".to_string(), Language::English, "").unwrap();

        //Add signer mnemonics
        b.add_signer_from_mnemonic(&mnemonic_1)?;
        b.add_signer_from_mnemonic(&mnemonic_2)?;
        b.add_signer_from_mnemonic(&mnemonic_3)?;

        //Build and return
        Ok(b.build()?)
    }

    fn nested_segwit_from_shared_keys_slip() -> Result<MultisigHDWallet, HDWError> {
        //Create new builder instance
        let mut b = MultisigHDWalletBuilder::new();
                        
        //Set wallet meta data
        //Builder will infer wallet data from keys in this case
        b.set_quorum(2);

        //Set keys
        let key_1 = "Ypub6ktoBaeGEYNuTuEY2xQiPuKnSUB1zTHg52YTovScv21GMBLzGUMnMbhhW5VeRm3xQ89UyFxzjQATL2d9AQfk3vNvwhAqSzDYdhhUvXYRhcG";
        let key_2 = "Ypub6k5FZrFGdBo2X1SqSR5fGiv731Nv6XcneHC6aQCxScjuuNZ2x9A2G7iKDVzzo4ciszdEaB21m6De4ZRMrZ6YS1fB7pLzawhoxkGWX8Le9zw";
        let key_3 = "Ypub6khkb7kSvJ69iEWRY3TyZEDHJcRUtp2re3fjD8QTQpQPUR9UXwGRhxXkQhKocD4fJXmUzNcHAE1kcD9M7SgdxRUquf2jXs1Y6w8A5CyPqKn";

        //Add signer master keys
        b.add_signer_from_xpub(key_1)?;
        b.add_signer_from_xpub(key_2)?;
        b.add_signer_from_xpub(key_3)?;

        //Build and return
        Ok(b.build()?)
    }

    fn nested_segwit_from_a_bit_of_everything() -> Result<MultisigHDWallet, HDWError> {
        //Create new builder instance
        let mut b = MultisigHDWalletBuilder::new();
                        
        //Set wallet meta data
        //Builder will infer wallet data from keys in this case
        b.set_quorum(2);
 
        //Set keys
        let mnemonic_1 = Mnemonic::from_phrase("valid wife trash caution slide coach lift visual goose buzz off silly".to_string(), Language::English, "").unwrap();
        let key_2 = "Ypub6k5FZrFGdBo2X1SqSR5fGiv731Nv6XcneHC6aQCxScjuuNZ2x9A2G7iKDVzzo4ciszdEaB21m6De4ZRMrZ6YS1fB7pLzawhoxkGWX8Le9zw";
        let key_3 = "Ypub6khkb7kSvJ69iEWRY3TyZEDHJcRUtp2re3fjD8QTQpQPUR9UXwGRhxXkQhKocD4fJXmUzNcHAE1kcD9M7SgdxRUquf2jXs1Y6w8A5CyPqKn";
 
        //Add signer master keys
        b.add_signer_from_mnemonic(&mnemonic_1)?;
        b.add_signer_from_xpub(key_2)?;
        b.add_signer_from_xpub(key_3)?;
 
        //Build and return
        Ok(b.build()?)
    }

    #[test]
    fn good_legacy_multisig_wallet() -> Result<(), HDWError> {
        let mut wallets = vec![];
        wallets.push( legacy_from_mnemonics()? );            //need cosigner index
        wallets.push( legacy_from_shared_keys_slip()? );     //no cosigner index
        wallets.push( legacy_from_a_bit_of_everything()? );  //need cosigner index
        
        

        //Check addresses
        for wallet in wallets {
            assert_eq!(wallet.wallet_type, MultisigWalletType::P2SH);
            assert_eq!(wallet.address_at(false, 0)?, "34NZeYBNpp11XjuWc2CG59PCrwFUDteqXU");
            assert_eq!(wallet.address_at(true, 0)?, "3MuWRVuFqyEjywRerEHacP5Y3zBnMMRJ99");
        }
        

        Ok(())
    }

    fn legacy_from_mnemonics() -> Result<MultisigHDWallet, HDWError> {
        //Create new builder instance
        let mut b = MultisigHDWalletBuilder::new();
                
        //Set wallet meta data
        //Account #0, Nested segwit, Bitcoin Mainnet
        b.set_quorum(2);
        b.set_type(MultisigWalletType::P2SH);

        //Set mnemonics
        let mnemonic_1 = Mnemonic::from_phrase("valid wife trash caution slide coach lift visual goose buzz off silly".to_string(), Language::English, "").unwrap();
        let mnemonic_2 = Mnemonic::from_phrase("salon cloth blossom below emotion buffalo bone dilemma dinosaur morning interest gentle".to_string(), Language::English, "").unwrap();
        let mnemonic_3 = Mnemonic::from_phrase("desert shock swift grant chronic invite gasp jelly round design sand liquid".to_string(), Language::English, "").unwrap();

        //Add signer mnemonics
        b.add_signer_from_mnemonic(&mnemonic_1)?;
        b.add_signer_from_mnemonic(&mnemonic_2)?;
        b.add_signer_from_mnemonic(&mnemonic_3)?;

        //Build and return
        Ok(b.build()?)
    }

    fn legacy_from_shared_keys_slip() -> Result<MultisigHDWallet, HDWError> {
        //Create new builder instance
        let mut b = MultisigHDWalletBuilder::new();
                        
        //Set wallet meta data
        //Builder will infer wallet data from keys in this case
        b.set_quorum(2);

        //Set keys
        let key_1 = "xpub6AUp4u2wjUAoR1QZGxgEfSnxrYdtaVcPUFWar4CTAYhvi64PYDHkx2qS58yoYVvHuYm5ErDfkUxAUDqkBwSroR2VMoQmqTT34TWD5xWz2xr";
        let key_2 = "xpub6A73AbdSz9JHfBiBUBQdzfTLUT7RZ6EgjRckgniJdpseUA3XAZG23kLGVC3iy4K6oyToMVj5CmvyaeyWsQQMje1tFJReVjQNt6ZZKfbmoBt";
        let key_3 = "xpub6BNSJ7M1i51wkmLn18swH14MMuiVLvvJJv66EaFDqkCpX3pv6N287iqrE1BkocAXxCi9uqfTEmvB2yZc1JQBa8Ax6Q9Fk4XGwXZwtMPSQCW";

        //Add signer master keys
        b.add_signer_from_xpub(key_1)?;
        b.add_signer_from_xpub(key_2)?;
        b.add_signer_from_xpub(key_3)?;

        //Build and return
        Ok(b.build()?)
    }

    fn legacy_from_a_bit_of_everything() -> Result<MultisigHDWallet, HDWError> {
        //Create new builder instance
        let mut b = MultisigHDWalletBuilder::new();
                                
        //Set wallet meta data
        //Builder will infer wallet data from keys in this case
        b.set_quorum(2);

        //Set keys
        let mnemonic_1 = Mnemonic::from_phrase("valid wife trash caution slide coach lift visual goose buzz off silly".to_string(), Language::English, "").unwrap();
        let mnemonic_2 = Mnemonic::from_phrase("salon cloth blossom below emotion buffalo bone dilemma dinosaur morning interest gentle".to_string(), Language::English, "").unwrap();
        let key_3 = "xpub6BNSJ7M1i51wkmLn18swH14MMuiVLvvJJv66EaFDqkCpX3pv6N287iqrE1BkocAXxCi9uqfTEmvB2yZc1JQBa8Ax6Q9Fk4XGwXZwtMPSQCW";

        //Add signer master keys
        b.add_signer_from_mnemonic(&mnemonic_1)?;
        b.add_signer_from_mnemonic(&mnemonic_2)?;
        b.add_signer_from_xpub(key_3)?;

        //Build and return
        Ok(b.build()?)
    }

    #[test]
    fn bad_quorum_failures() -> Result<(), HDWError> {
        /*
            Testing bad quorum instances in multisig wallet builder
        
            Test cases:
                Case 1: 
                    Quorum = 0,
                    Keys provided = 1
                    Expected err = Bad quorum due to it being zero
                Case 2:
                    Quorum = 1
                    Keys provided = 2
                    Expected err = Bad quorum due to it being larger than keys provided
        */
        let quorum_cases = vec![0, 2];
        let key_cases =    vec![1, 1];
        let expected_err = vec![
            HDWError::BadQuorum(0),
            HDWError::BadQuorum(2)
        ];

        for i in 0..2 {
            let mut b = MultisigHDWalletBuilder::new();

            //Set quorum
            b.set_quorum(quorum_cases[i]);

            //Set keys
            for _ in 0..key_cases[i] {
                let key = Mnemonic::new(PhraseLength::Twelve, Language::English, "").unwrap();
                b.add_signer_from_mnemonic(&key)?;
            }

            //Try to build
            match b.build() {
                Ok(_) => assert!(false),
                Err(x) => assert_eq!(x, expected_err[i])
            }
        }

        Ok(())
    }

    #[test]
    fn bad_signer_count_failure() -> Result<(), HDWError> {
        /*
            Testing bad signer counts in multisig wallet builders.
        
            Test cases:
                Case 1:
                    Signers: 0
                    Expected err: Missing fields as no signers are set
                Case 2:
                    Signers: 16
                    Expected err: Index too large as there are too many signers
        */
        let signer_count = vec![0, 16];
        let expected_err = vec![
            HDWError::MissingFields,
            HDWError::IndexTooLarge(16)
        ];

        for i in 0..2 {
            let mut b = MultisigHDWalletBuilder::new();

            //Set keys
            for _ in 0..signer_count[i] {
                let key = Mnemonic::new(PhraseLength::Twelve, Language::English, "").unwrap();
                b.add_signer_from_mnemonic(&key)?;
            }

            //Try to build
            match b.build() {
                Ok(_) => assert!(false),
                Err(x) => assert!(x == expected_err[i])
            }
        }

        Ok(())
    }

    #[test]
    fn type_discrepancy_failure() -> Result<(), HDWError> {
        //Tests multisig wallet builds where signers given are of a different type or a network
        //Adding the second key will result in an error
        
        //Test cases:
        let key_1 = vec![
            /* Mainnnet legacy xpub */             "xpub6BNSJ7M1i51wkmLn18swH14MMuiVLvvJJv66EaFDqkCpX3pv6N287iqrE1BkocAXxCi9uqfTEmvB2yZc1JQBa8Ax6Q9Fk4XGwXZwtMPSQCW",
            /* Mainnnet legacy xpub */             "xpub6BNSJ7M1i51wkmLn18swH14MMuiVLvvJJv66EaFDqkCpX3pv6N287iqrE1BkocAXxCi9uqfTEmvB2yZc1JQBa8Ax6Q9Fk4XGwXZwtMPSQCW",
            /* Mainnnet nested segwit SLIP Ypub */ "Ypub6ktoBaeGEYNuTuEY2xQiPuKnSUB1zTHg52YTovScv21GMBLzGUMnMbhhW5VeRm3xQ89UyFxzjQATL2d9AQfk3vNvwhAqSzDYdhhUvXYRhcG",
            /* Testnet legacy tpub */              "tpubD6NzVbkrYhZ4WsKoTUCyQjVK66nCqT41aYQLPZ6h49G5rgLQuuG7Nh9upmijk4PuDT2DRqXiSJaUfnpR6SbXe1jBF29ebVrTxw5Xjt9R2C5",
            /* Testnet nested segwit SLIP Upub */  "Upub5JQfBberxLXY8hFueeEALeYirjJUsn11Y78uKMaUwssL1zVtts2XYVNhKCpCgFVkFLYwU8qTtRnXY7FBWRxuAwhvYecTExNh8cndnF24cZD",
            /* Testnet native segwit SLIP Vpub */  "Vpub5dEvVGKn7251ztuSZrtpeSfonFbDAuCfQRbDVq6emVu81vf7a4xmGzVZY3UkqhV5W4AHv4wrJ1S5AfqRioP5wEGT4uyCrFK2YysmXguKNgq"
        ];
        let key_2 = vec![
            /* Mainnnet nested segwit SLIP Ypub */ "Ypub6ktoBaeGEYNuTuEY2xQiPuKnSUB1zTHg52YTovScv21GMBLzGUMnMbhhW5VeRm3xQ89UyFxzjQATL2d9AQfk3vNvwhAqSzDYdhhUvXYRhcG",
            /* Mainnnet native segwit SLIP Zpub */ "Zpub75j4VFKBPDvPLXWNZ6WqLvW6WJa2FYKVSKcqew31p35h3snWWDGSkQDmR9evjNcN5Me131afLP2ctT33e2J1vvsTVYdF5LfvsbeJsTwf1c4",
            /* Mainnnet native segwit SLIP Zpub */ "Zpub75j4VFKBPDvPLXWNZ6WqLvW6WJa2FYKVSKcqew31p35h3snWWDGSkQDmR9evjNcN5Me131afLP2ctT33e2J1vvsTVYdF5LfvsbeJsTwf1c4",
            /* Mainnet legacy xpub */              "xpub6BNSJ7M1i51wkmLn18swH14MMuiVLvvJJv66EaFDqkCpX3pv6N287iqrE1BkocAXxCi9uqfTEmvB2yZc1JQBa8Ax6Q9Fk4XGwXZwtMPSQCW",
            /* Mainnet nested segwit SLIP Ypub */  "Ypub6ktoBaeGEYNuTuEY2xQiPuKnSUB1zTHg52YTovScv21GMBLzGUMnMbhhW5VeRm3xQ89UyFxzjQATL2d9AQfk3vNvwhAqSzDYdhhUvXYRhcG",
            /* Mainnet native segwit SLIP Zpub */  "Zpub75j4VFKBPDvPLXWNZ6WqLvW6WJa2FYKVSKcqew31p35h3snWWDGSkQDmR9evjNcN5Me131afLP2ctT33e2J1vvsTVYdF5LfvsbeJsTwf1c4"
        ];
        let expected_err = HDWError::TypeDiscrepancy;

        for i in 0..5 {
            let mut b = MultisigHDWalletBuilder::new();

            //Set keys
            b.add_signer_from_xpub(key_1[i])?;
            match b.add_signer_from_xpub(key_2[i]) {
                Ok(_) => assert!(false),
                Err(x) => assert!(x == expected_err)
            }
        }

        Ok(())
    }

    #[test]
    fn bad_signer_key_failure() {
        //Test cases:
        let bad_shared_signers = vec![
            "obviously this is not a valid key",
            "xpubThisIsNotAValidKey",
            "YpubThisIsAlsoNotAValidKey",
            "ZpubThisIsDefinatelyNotAGoodKey",
            "tpubThisIsNotAValidTestnetKey",
            "UpubAgainNotAValidTestnetKey",
            "VpubAnotherBadKeyToTest",
            "",
        ];

        let bad_root_signers = vec![
            "obviously this is not a valid key",    
            "xprvThisIsNotAValidKey",
            "YprvThisIsAlsoNotAValidKey",
            "ZprvThisIsDefinatelyNotAGoodKey",
            "tprvThisIsNotAValidTestnetKey",
            "UprvAgainNotAValidTestnetKey",
            "VprvAnotherBadKeyToTest",
            ""
        ];

        for i in 0..bad_shared_signers.len() {
            let mut b = MultisigHDWalletBuilder::new();
            //Add the bad shared signer
            match b.add_signer_from_xpub(bad_shared_signers[i]) {
                Ok(_) => assert!(false),
                Err(_) => assert!(true)
            }

            //Add the bad root signer
            match b.add_signer_from_xprv(bad_root_signers[i]) {
                Ok(_) => assert!(false),
                Err(_) => assert!(true)
            }
        }
    }

    //Tests if extracted private keys create the same address as the wallet creates.
    #[test]
    fn private_key_extraction()-> Result<(), HDWError> {
        //Create new 2-of-3 multisig wallet
        let mut b = MultisigHDWalletBuilder::new();
        b.set_quorum(2);
        let mnemonic_1 = Mnemonic::from_phrase("valid wife trash caution slide coach lift visual goose buzz off silly".to_string(), Language::English, "").unwrap();
        let mnemonic_2 = Mnemonic::from_phrase("salon cloth blossom below emotion buffalo bone dilemma dinosaur morning interest gentle".to_string(), Language::English, "").unwrap();
        let mnemonic_3 = Mnemonic::from_phrase("desert shock swift grant chronic invite gasp jelly round design sand liquid".to_string(), Language::English, "").unwrap();
        b.add_signer_from_mnemonic(&mnemonic_1)?;
        b.add_signer_from_mnemonic(&mnemonic_2)?;
        b.add_signer_from_mnemonic(&mnemonic_3)?;
        let wallet = b.build()?;

        //Get the unlockers from mnemonics used
        let unlocker_1 = Unlocker::from_mnemonic(&mnemonic_1)?;
        let unlocker_2 = Unlocker::from_mnemonic(&mnemonic_2)?;
        let unlocker_3 = Unlocker::from_mnemonic(&mnemonic_3)?;

        //Extract private keys for the first receiving address and create an address from it.
        //Compare the address created to the one the wallet spits out
        let address = Address::P2WSH(
            RedeemScript::multisig(2, &vec![
                wallet.address_private_key(false, 0, &unlocker_1)?.get_pub(),
                wallet.address_private_key(false, 0, &unlocker_2)?.get_pub(),
                wallet.address_private_key(false, 0, &unlocker_3)?.get_pub()
            ]).unwrap(),
            Network::Bitcoin
        ).to_string().unwrap();
        assert_eq!(address, wallet.address_at(false, 0)?);

        Ok(())
    }
}