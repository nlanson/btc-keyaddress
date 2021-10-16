/*
    Module implementing Multisig HD Wallet data structures

    Todo:
        - SLIP-0132 support (outlined in lib.rs notes)
        - The pathing trait could be used for Singlesig HDWallets as well.
        - The pathing trait could take in custom paths from master (with unlocker)
        - Is there a better way to implement an Unlocker for multisig?
          Currently, the unlocker unlocks a single key at a time.
          If the unlocker takes in many keys at a time, how will it return the valid keys?
        
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
    util::{
        Network,
        try_into, as_u32_be
    },
    encoding::bs58check::{
        VersionPrefix, decode
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
        let bytes = match decode(&key.to_string()) {
            Ok(x) => x,
            Err(_) => return Err(HDWError::BadKey())
        };

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

/**
    Builder struct to make creating HD Multisig Wallets easier.
    Can only create standard BIP-45 or BIP-48 wallets for the time being.
*/
const MAX_KEYS_FOR_SETUP: u8 = 15;
pub struct MultisigHDWalletBuilder {
    wallet_type: Option<MultisigWalletType>, //Defaults to P2WSH
    quorum: Option<u8>,                      //Required
    network: Option<Network>,                //Defaults to Bitcoin
    account_index: Option<u32>,              //Defaults to 0

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
            //signers: vec![],

            master_signer_keys: vec![],
            shared_signer_keys: vec![],
            //inferred_wallet_data: vec![]
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

    //Add a new signer from Mnemonic
    pub fn add_signer_from_mnemonic(&mut self, mnemonic: &Mnemonic) -> Result<(), HDWError> {    
        let signer_master_key = Xprv::from_mnemonic(mnemonic)?;

        //No data to extract from mnemonic. Only store master key
        self.master_signer_keys.push(signer_master_key);

        Ok(())
    }

    //Add a new signer from root Xprv key
    //If a SLIP-0132 key is given, reject or add to shared_signers list?
    pub fn add_signer_from_xprv(&mut self, signer_master_key: &str) -> Result<(), HDWError> {
        //If the key is a SLIP-0132 Multisig private key, get the xpub of the key and add to share level
        
        //Store the inferred wallet type and network if they are the same as the others.
        self.add_inferred_type(signer_master_key)?;
        
        //Store the key
        let key: Xprv = Xprv::from_str(signer_master_key)?;
        self.master_signer_keys.push(key);

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
        let path_to_shared = Self::to_shared_from_master(wallet_type, network, account_index);
        let mut shared_public_keys = self.shared_signer_keys.clone();
        shared_public_keys.append(
            &mut self.master_signer_keys.iter().map(|x| {
                x.derive_from_path(&path_to_shared)
                .unwrap()
                .get_xpub()
            }).collect::<Vec<Xpub>>()
        );
        
        //Sort the shared keys in lexicographical order of PubKey
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

    //Creates the redeem script at a given standard path
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
    
    //Generates an address at a given standard path
    pub fn address_at(
        &self,
        cosigner_index: Option<u8>,
        change: bool,
        address_index: u32
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;

    #[test]
    fn successful_multisig_hdwallet_building() -> Result<(), HDWError> {
        let mut wallets = vec![];
        wallets.push( create_from_mnemonics()? );
        wallets.push( create_from_master_keys()? );
        wallets.push( create_from_shared_keys_slip()? );
        wallets.push( create_from_shared_keys_nonslip()? );
        wallets.push( from_a_bit_of_everything()? );


        //Check addresses
        for wallet in wallets {
            assert_eq!(wallet.address_at(None, false, 0)?, "bc1q2amk0dcqqs2gqfa6ju2td2xx42zz93n80paztjueltjefjugyv0qh6dtdx");
            assert_eq!(wallet.address_at(None, true, 0)?, "bc1qcgsxne2nppzu38yshxmls4ayzje8k3xk48r592wvpuyzgfayayasweyn85");
        }
        

        Ok(())
    }

    //Test builder using mnemonics and setting data
    fn create_from_mnemonics() -> Result<MultisigHDWallet, HDWError> {
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

    fn create_from_master_keys() -> Result<MultisigHDWallet, HDWError> {
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

    fn create_from_shared_keys_slip() -> Result<MultisigHDWallet, HDWError> {
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

    fn create_from_shared_keys_nonslip() -> Result<MultisigHDWallet, HDWError> {
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

    fn from_a_bit_of_everything() -> Result<MultisigHDWallet, HDWError> {
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
}