/*
    Implementation of a PKH HD Wallet following
    BIP-32, BIP-44, BIP-49 and BIP-84.

    Custom derivation paths are also supported but require
    external path management.

    Todo:
        - Remove old redundant methods that have been replaced by builder struct and pathing trait.
        - Write unit tests for builder testing successful and failing build cases and comapring derived
          and expected addresses
        - Use new derivation attribute in HDWallet struct replacing removed pathing methods
        - Unify locked and watch only trait methods into a single generic impl
        
            ****************
            ** UNIT TESTS **
            ****************
*/


use crate::{
    bip39::Mnemonic,
    key::{
        PrivKey,
        PubKey,
        Key
    },
    hdwallet::{
        ExtendedKey, Xprv, Xpub, 
        HDWError, ChildOptions, Path
    },
    encoding::{
        bs58check::decode,
        bs58check::VersionPrefix,
        ToVersionPrefix
    },
    util::{
        Network,
        as_u32_be,
        try_into
    }
};

#[derive(Debug, Copy, Clone, PartialEq)]
#[allow(non_camel_case_types)]
pub enum WalletType {
    P2PKH,
    P2WPKH,
    P2SH_P2WPKH
}

impl WalletType {
    /**
        Returns the wallet type from an extended key string.
        Does it by viewing the prefix  
    */
    pub fn from_xkey(key: &str) -> Result<Self, HDWError> {
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
                VersionPrefix::Tpub => Ok(WalletType::P2PKH),
                //Nested Segwit
                VersionPrefix::Yprv |
                VersionPrefix::Ypub |
                VersionPrefix::Uprv |
                VersionPrefix::Upub => Ok(WalletType::P2SH_P2WPKH),
                //Native Segwit
                VersionPrefix::Zprv |
                VersionPrefix::Zpub |
                VersionPrefix::Vprv |
                VersionPrefix::Vpub => Ok(WalletType::P2WPKH),
                
                _ => return Err(HDWError::BadKey())
            },
            
            //Return an error if not valid
            _ => return Err(HDWError::BadKey())
        }
    }
}


impl ToVersionPrefix for WalletType {
    fn public_version_prefix(&self, network: Network) -> VersionPrefix {
        match &self {
            WalletType::P2PKH => match network {
                Network::Bitcoin => VersionPrefix::Xpub,
                Network::Testnet => VersionPrefix::Tpub
            },
            WalletType::P2SH_P2WPKH => match network {
                Network::Bitcoin => VersionPrefix::Ypub,
                Network::Testnet => VersionPrefix::Upub
            },
            WalletType::P2WPKH => match network {
                Network::Bitcoin => VersionPrefix::Zpub,
                Network::Testnet => VersionPrefix::Vpub
            },
        }
    }

    fn private_version_prefix(&self, network: Network) -> VersionPrefix {
        match &self {
            WalletType::P2PKH => match network {
                Network::Bitcoin => VersionPrefix::Xprv,
                Network::Testnet => VersionPrefix::Tprv
            },
            WalletType::P2SH_P2WPKH => match network {
                Network::Bitcoin => VersionPrefix::Yprv,
                Network::Testnet => VersionPrefix::Uprv
            },
            WalletType::P2WPKH => match network {
                Network::Bitcoin => VersionPrefix::Zprv,
                Network::Testnet => VersionPrefix::Vprv
            },
        }
    }
}

pub struct HDWalletBuilder<'builder> {
    wallet_type: Option<WalletType>,         //Defaults to P2WKH
    network: Option<Network>,                //Defaults to Bitcoin
    account_index: Option<u32>,              //Defaults to 0
    derivation: Option<&'builder str>,       //Default depends on wallet_type

    master_signer_key: Option<Xprv>,         //Creating a wallet from a mnemonic of xprv key.
    shared_signer_key: Option<Xpub>          //Creating wallet from an xpub key.
}

pub trait HDStandardPathing {
    //Returns the standard path from a root key to account level key
    fn to_shared_from_master(
        wallet_type: WalletType,
        network: Network,
        account_index: u32
    ) -> Path {
        //Purpose
        let mut path = match wallet_type {
            WalletType::P2WPKH => Path::from_str("m/84'").unwrap(),
            WalletType::P2SH_P2WPKH => Path::from_str("m/49'").unwrap(),
            WalletType::P2PKH => Path::from_str("m/44'").unwrap(),
        };

        //Coin type
        match network {
            Network::Bitcoin => path.add_level(ChildOptions::Hardened(0)),
            Network::Testnet => path.add_level(ChildOptions::Hardened(1))
        }

        //Account index
        path.add_level(ChildOptions::Hardened(account_index));

        
        path
    }

    //Returns the path from a account level key to an address
    fn to_address_from_shared(
        change: bool,
        address_index: u32
    )-> Path {
        let mut path = Path::empty();
        path.add_level(ChildOptions::Normal(change as u32));
        path.add_level(ChildOptions::Normal(address_index));

        path
    }

    //Returns the path from a root key to an address
    fn to_address_from_master(
        wallet_type: WalletType,
        network: Network,
        account_index: u32,
        change: bool,
        address_index: u32
    ) -> Path {
        let mut path = Self::to_shared_from_master(wallet_type, network, account_index);
        path.append(&Self::to_address_from_shared(change, address_index));

        path
    }
}

impl<'builder> HDStandardPathing for HDWalletBuilder<'builder> { }
impl<'builder> HDWalletBuilder<'builder> {
    //Return a new builder instance
    pub fn new() -> Self {
        Self {
            wallet_type: None, 
            network: None, 
            account_index: None,
            derivation: None,
            master_signer_key: None,
            shared_signer_key: None
        }
    }

    //Set wallet type
    pub fn set_type(&mut self, wallet_type: WalletType) {
        self.wallet_type = Some(wallet_type);
    }

    //Set network
    pub fn set_network(&mut self, network: Network) {
        self.network = Some(network);
    }

    //Set account index
    pub fn set_account_index(&mut self, account_index: u32) {
        self.account_index = Some(account_index);
    }

    //Use a custom derivation path to shared
    pub fn set_custom_derivation(&mut self, path: &'builder str) {
        self.derivation = Some(path);
    }

    //Set a signer from a mnemonic
    pub fn set_signer_from_mnemonic(&mut self, mnemonic: &Mnemonic) -> Result<(), HDWError> {
        let signer_master_key = Xprv::from_mnemonic(mnemonic)?;

        //No data to extract from mnemonic. Only store master key
        self.master_signer_key = Some(signer_master_key);

        Ok(())
    }

    //Set a signer from a root private key
    pub fn set_signer_from_xprv(&mut self, signer_master_key: &str) -> Result<(), HDWError> {
        self.add_inferred_type(signer_master_key)?;

        let key: Xprv = Xprv::from_str(signer_master_key)?;
        self.master_signer_key = Some(key);

        Ok(())
    }

    //Set a signer from shared public key
    pub fn set_signer_from_xpub(&mut self, signer_shared_key: &str) -> Result<(), HDWError> {
        self.add_inferred_type(signer_shared_key)?;

        let key: Xpub = Xpub::from_str(signer_shared_key)?;
        self.shared_signer_key = Some(key);

        Ok(())
    }

    //This method runs everytime a signer is added via xprv or xpub key.
    //It takes in the key and extracts wallet type and network info from it.
    //Copied and adapted from hdmultisig.rs
    fn add_inferred_type(&mut self, key: &str) -> Result<(), HDWError> {
        //Extract the wallet meta data from the key
        let wallet_type: WalletType = WalletType::from_xkey(key)?;
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

    //Extracts wallet type, network and acocunt index from self if present.
    //Uses default values if not present.
    fn extract_or_default(&self) -> (WalletType, Network, u32) {
        let wallet_type = self.wallet_type.unwrap_or(WalletType::P2WPKH);
        let network = self.network.unwrap_or(Network::Bitcoin);
        let account_index = self.account_index.unwrap_or(0);

        (wallet_type, network, account_index)
    }

    //Build the HDWallet using given information.
    pub fn build(&self) -> Result<HDWallet, HDWError> {
        //Return an error if no keys are provided or if two keys are provided
        if self.master_signer_key.is_none() && self.shared_signer_key.is_none() { return Err(HDWError::MissingFields) }
        if self.master_signer_key.is_some() && self.shared_signer_key.is_some() { return Err(HDWError::BadKey()) }
        
        //Extract wallet type, networka and account index or resort to defaults if not available.
        let (wallet_type, network, account_index) = self.extract_or_default();
        
        //Create the path to shared level from root
        let path_to_shared = match self.derivation {
            Some(x) => Path::from_str(x)?,
            None => Self::to_shared_from_master(wallet_type, network, account_index)
        };  

        //Get the shared key from given info
        let share_key = match self.master_signer_key {
            //If the provided key is the master key, derive to share level and use.
            Some(x) => x.derive_from_path(&path_to_shared)?.get_xpub(),

            //Else, the provided key has to be the shared key. Leave as is and use.
            None => self.shared_signer_key.unwrap()
        };

        //Create and return the wallet
        Ok(HDWallet {
            account_public_key: share_key,
            wallet_type,
            network,
            account_index,
            derivation: path_to_shared
        })
    }

}

#[derive(Debug, Clone)]
pub struct HDWallet {
    //The stored account level key
    //This is the only key required to generate addresses
    account_public_key: Xpub,

    //The type of wallet
    //This is used in determining the purpose level path and to generate addresses
    pub wallet_type: WalletType,

    //The BIP-44/49/84 account number
    account_index: u32,
    
    //The network the HD wallet is going to be used on.
    //This is used to determine the coin-type level path and in generating addresses
    pub network: Network,

    //This path is used to get to the share level from master keys.
    //Standard derivation paths include BIP-44, 49 and 84.
    derivation: Path
}

/**
    A collection of methods in the HD Wallet that can be invoked without an unlocker.
*/
#[allow(unused_variables)]
pub trait WatchOnly {
    /**
        Return the account level wallet xpub key.
        This key can be used to import watch only wallets
        with other providers.
    */
    fn account_public_key(&self) -> Xpub;

    /**
        Return the address level public key
        derived from the account public key. 
    */
    fn address_public_key(
        &self,
        change: bool,
        address_index: u32
    ) -> Result<PubKey, HDWError>;
    
    /**
        Return an addresses at the given BIP-44/49/84 compliant deriveration path.
    */
    fn address_at(
        &self,
        change: bool,
        address_index: u32
    ) -> Result<String, HDWError>;
}

/**
    A collection of methods in the HD Wallet that require an unlocker and could
    spend funds locked in the HD wallet.
*/
#[allow(unused_variables)]
pub trait Locked<T> {
    //Returns the master private key
    fn master_private_key(&self, unlocker: &T) -> Result<Xprv, HDWError>;

    //Returns the account private key
    fn account_private_key(&self, unlocker: &T)-> Result<Xprv, HDWError>;

    //Returns the address level private key given a change boolean and address index
    fn address_private_key(&self, change: bool, address_index: u32, unlocker: &T)-> Result<PrivKey, HDWError>;

    /**
        Returns the extended private key at a custom path
        
        The resulting Xprv key can be used to derive addresses and keys at the path using methods written in
        the Xprv and ExtendedKeys struct and trait. 
        This can be used with wallets that use custom non-standard derivation paths.
    */
    fn custom_path_extended_private_key(&self, custom_path: &str, unlocker: &T) -> Result<Xprv, HDWError>;
}

/**
    Unlocker struct that unlocks locked methods in the HDWallet struct
*/
#[derive(Debug, Clone)]
pub struct Unlocker {
    pub master_private_key: Xprv
}

impl Unlocker {
    pub fn from_mnemonic(mnemonic: &Mnemonic) -> Result<Self, HDWError> {
        Ok(Self {
            master_private_key: Xprv::from_mnemonic(mnemonic)?
        })
    }

    pub fn from_master_private(key: &str) -> Result<Self, HDWError> {
        Ok(Self {
            master_private_key: Xprv::from_str(key)?
        })
    }
}

impl HDWallet {
    /**
        Create a watch only wallet from mnemonic phrase

        Will be removed
    */
    pub fn from_mnemonic(mnemonic: &Mnemonic, wallet_type: WalletType, account_index: u32, network: Network) -> Result<Self, HDWError> {
        
        let account_public_key = Xprv::from_mnemonic(mnemonic)?
                                .derive_from_path(&Self::account_path(&wallet_type, account_index, network))?
                                .get_xpub();
        
        Ok(Self {
            account_public_key,
            wallet_type,
            account_index,
            network,
            derivation: Self::account_path(&wallet_type, account_index, network)
        })
    }


    /**
        Create a watch only wallet from a master private key

        reject SLIP keys

        Will be removed
    */
    pub fn from_master_private(key: &str, account_index: u32) -> Result<Self, HDWError> {
        let wallet_type = WalletType::from_xkey(key)?;
        let network = match Network::from_xkey(key) {
            Ok(x) => x,
            Err(_) => return Err(HDWError::BadKey())
        };

        let account_public_key = Xprv::from_str(key)?
                                .derive_from_path(&Self::account_path(&wallet_type, account_index, network))?
                                .get_xpub();

        Ok(Self {
            account_public_key,
            wallet_type,
            account_index,
            network,
            derivation: Self::account_path(&wallet_type, account_index, network)
        })
    }


    /**
        Create a watch only wallet from a master public key

        can take in SLIP keys

        Will be removed
    */
    pub fn from_account_public(key: &str, account_index: u32) -> Result<Self, HDWError> {
        let wallet_type = WalletType::from_xkey(key)?;
        let network = match Network::from_xkey(key) {
            Ok(x) => x,
            Err(_) => return Err(HDWError::BadKey())
        };
        
        let account_public_key = Xpub::from_str(key)?;

        Ok(Self {
            account_public_key,
            wallet_type,
            account_index,
            network,
            derivation: Self::account_path(&wallet_type, account_index, network)
        })
    }


    /**
        Returns a path from the root to purpose level

        Will be removed
    */
    fn purpose_path(wallet_type: &WalletType) -> Path {
        let mut path = String::from("m/");

        //Purpose field
        match wallet_type {
            WalletType::P2PKH => path.push_str("44'"),
            WalletType::P2WPKH => path.push_str("84'"),
            WalletType::P2SH_P2WPKH => path.push_str("49'"),
        }

        Path::from_str(&path).unwrap()
    }

    /**
        Returns a path from the root to coin type level

        Will be removed
    */
    fn coin_type_path(wallet_type: &WalletType, network: Network) -> Path {
        let mut path = Self::purpose_path(wallet_type);
        path.children.push(ChildOptions::Hardened(match network {
            Network::Bitcoin => 0,
            Network::Testnet => 1
        }));

        path
    }

    /**
        Returns a path from the root to account level

        Will be removed
    */
    fn account_path(wallet_type: &WalletType, account_index: u32, network: Network) -> Path {
        let mut path = Self::coin_type_path(wallet_type, network);
        //WalletType::path(wallet_type, network);
        path.children.push(ChildOptions::Hardened(account_index));

        path
    }

    /**
        Create the path to the address level given self, change boolean and address index

        Returns a path from the root to address level

        Will be removed
    */
    fn address_path(&self, change: bool, address_index: u32) -> Path {
        let mut path = Self::account_path(&self.wallet_type, self.account_index, self.network);
        path.children.push(ChildOptions::Normal(change as u32));
        path.children.push(ChildOptions::Normal(address_index));

        path
    }

    /**
        Takes in an instance of self and an unlocker and checks if the unlocker corresponds to self. 

        Update to use StandardPathing trait
    */
    fn unlock(&self, unlocker: &Unlocker) -> Result<(), HDWError> {
        //If the account key derived from the unlocker is equal to the stored account key,
        //return the master private key in the unlocker.
        let derived_account_key = unlocker.master_private_key
                                    .derive_from_path(&Self::account_path(&self.wallet_type, self.account_index, self.network))?
                                    .get_xpub()
                                    .key::<33>();

        if derived_account_key == self.account_public_key().key::<33>() {
            return Ok(())
        }

        Err(HDWError::BadKey())
    }


    /**
        Return the master public key of self given a valid unlocker.

        This method is not bundled with the Spendable trait as it does not allow
        for funds to be spent.
    */
    pub fn master_public_key(&self, unlocker: &Unlocker) -> Result<Xpub, HDWError> {
        Ok(self.master_private_key(unlocker)?.get_xpub())
    }
}


impl WatchOnly for HDWallet {
    fn account_public_key(&self) -> Xpub {
        self.account_public_key.clone()
    }

    fn address_public_key(&self, change: bool, address_index: u32) -> Result<PubKey, HDWError> {
        //Deriving path working from the account level
        let mut path: Path = Path::empty();
        path.children.push(ChildOptions::Normal(change as u32));
        path.children.push(ChildOptions::Normal(address_index));

        Ok(
            self.account_public_key().derive_from_path(&path)?.get_pub()
        )
    }
    
    fn address_at(
        &self,
        change: bool,
        address_index: u32
    ) -> Result<String, HDWError>
    where Self: Sized
    {
        //Deriving path working from the account level
        let mut p: Path = Path::empty();
        p.children.push(ChildOptions::Normal(change as u32));
        p.children.push(ChildOptions::Normal(address_index));

        let address = self.account_public_key.derive_from_path(&p)?.get_address(&self.wallet_type, self.network);

        Ok(address)
    }
}

impl Locked<Unlocker> for HDWallet {
    fn master_private_key(&self, unlocker: &Unlocker) -> Result<Xprv, HDWError> {
        self.unlock(unlocker)?;
        
        Ok(unlocker.master_private_key.clone())
    }
    
    fn account_private_key(&self, unlocker: &Unlocker) -> Result<Xprv, HDWError> {
        self.unlock(unlocker)?;
        Ok(
            unlocker.master_private_key
                .derive_from_path(&Self::account_path(&self.wallet_type, self.account_index, self.network))?
        )                          
    }
    
    fn address_private_key(&self, change: bool, address_index: u32, unlocker: &Unlocker) -> Result<PrivKey, HDWError> {
        self.unlock(unlocker)?;
        
        let path = self.address_path(change, address_index);
        
        Ok(
            PrivKey::from_slice(
                &self.master_private_key(unlocker)?.derive_from_path(&path)?.key::<32>()
            ).unwrap()
        )
    }

    fn custom_path_extended_private_key(&self, custom_path: &str, unlocker: &Unlocker) -> Result<Xprv, HDWError> {
        self.unlock(unlocker)?;

        let path = Path::from_str(custom_path)?;

        Ok(unlocker.master_private_key.derive_from_path(&path)?)
    }
}