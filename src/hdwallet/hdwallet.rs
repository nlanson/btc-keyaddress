/*
    Implementation of a PKH HD Wallet following
    BIP-32, BIP-44, BIP-49 and BIP-84.

    Custom derivation paths are also supported but require
    external path management.
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
    encoding::bs58check::decode,
    util::Network
};

#[derive(Debug, Clone)]
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

        let prefix = &bytes[0..4];

        match prefix {
            &[0x04, 0x88, 0xAD, 0xE4] |
            &[0x04, 0x88, 0xB2, 0x1E] |
            &[0x04, 0x35, 0x83, 0x94] |
            &[0x04, 0x35, 0x87, 0xCF] => Ok(WalletType::P2PKH),
            &[0x04, 0xb2, 0x43, 0x0c] |
            &[0x04, 0xb2, 0x47, 0x46] |
            &[0x04, 0x5f, 0x18, 0xbc] |
            &[0x04, 0x5f, 0x1c, 0xf6] => Ok(WalletType::P2WPKH),
            &[0x04, 0x9d, 0x78, 0x78] |
            &[0x04, 0x9d, 0x7c, 0xb2] |
            &[0x04, 0x4a, 0x4e, 0x28] |
            &[0x04, 0x4a, 0x52, 0x62] => Ok(WalletType::P2SH_P2WPKH),
            _ => return Err(HDWError::BadKey())
        }
    }

    /**
        Returns the wallet network from the extended key string.
        Does it by viewing the prefix  
    */
    pub fn network_from_xkey(key: &str) -> Result<Network, HDWError> {
        let bytes = match decode(&key.to_string()) {
            Ok(x) => x,
            Err(_) => return Err(HDWError::BadKey())
        };

        let prefix = &bytes[0..4];

        match prefix {
            &[0x04, 0x35, 0x83, 0x94] |
            &[0x04, 0x35, 0x87, 0xCF] |
            &[0x04, 0x4a, 0x4e, 0x28] |
            &[0x04, 0x4a, 0x52, 0x62] |
            &[0x04, 0x5f, 0x18, 0xbc] |
            &[0x04, 0x5f, 0x1c, 0xf6] => Ok(Network::Testnet),
            &[0x04, 0x88, 0xAD, 0xE4] |
            &[0x04, 0x88, 0xB2, 0x1E] |
            &[0x04, 0x9d, 0x78, 0x78] |
            &[0x04, 0x9d, 0x7c, 0xb2] |
            &[0x04, 0xb2, 0x43, 0x0c] |
            &[0x04, 0xb2, 0x47, 0x46] => Ok(Network::Bitcoin),
            _ => return Err(HDWError::BadKey())
        }
    } 

    /**
        Returns the deriveration path for "m/purpose/coin_type" given a wallet type
        and network.
    */
    pub fn path(&self, network: Network) -> Path {
        let mut path = String::from("m/");

        //Purpose field
        match &self {
            WalletType::P2PKH => path.push_str("44'/"),
            WalletType::P2WPKH => path.push_str("84'/"),
            WalletType::P2SH_P2WPKH => path.push_str("49'/"),
        }

        //Coin type field
        match network {
            Network::Bitcoin => path.push_str("0'"),
            Network::Testnet => path.push_str("1'")
        }

        Path::from_str(&path).unwrap()
    }
}



#[derive(Debug, Clone)]
pub struct HDWallet {
    account_public_key: Xpub,
    pub wallet_type: WalletType,
    account_index: u32,
    pub network: Network
}

/**
    A collection of methods in the HD Wallet that can be invoked without an unlocker.
*/
#[allow(unused_variables)]
pub trait WatchOnly {
    /**
        Return the account level wallet xpub key.
        This key can be used to import watch only wallets
        with other providers. (Singlesig)
    */
    fn account_public_key(&self) -> Xpub { unimplemented!() }

    /**
        Return the address level public key
        derived from the account public key. 
        (Singlesig)
    */
    fn address_public_key(
        &self,
        change: bool,
        address_index: u32
    ) -> Result<PubKey, HDWError> { Err(HDWError::DefaultError) }
    
    /**
        Return an addresses at the given BIP-44/49/84 compliant deriveration path.
    */
    fn address_at(
        &self,
        change: bool,
        address_index: u32
    ) -> Result<String, HDWError> { Err(HDWError::DefaultError) }
}

/**
    A collection of methods in the HD Wallet that require an unlocker and could
    spend funds locked in the HD wallet.
*/
#[allow(unused_variables)]
pub trait Locked<T> {
    //Returns the master private key (Singlesig)
    fn master_private_key(&self, unlocker: &T) -> Result<Xprv, HDWError> { Err(HDWError::DefaultError) }

    //Returns the account private key (Singlesig)
    fn account_private_key(&self, unlocker: &T)-> Result<Xprv, HDWError> { Err(HDWError::DefaultError) }

    //Returns the address level private key given a change boolean and address index (Singlesig)
    fn address_private_key(&self, change: bool, address_index: u32, unlocker: &T)-> Result<PrivKey, HDWError> { Err(HDWError::DefaultError) }

    /**
        Returns the extended private key at a custom path (Singlesig)
        
        The resulting Xprv key can be used to derive addresses and keys at the path using methods written in
        the Xprv and ExtendedKeys struct and trait. 
        This can be used with wallets that use custom non-standard derivation paths.
    */
    fn custom_path_extended_private_key(&self, custom_path: &str, unlocker: &T) -> Result<Xprv, HDWError> { Err(HDWError::DefaultError) }
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
    */
    pub fn from_mnemonic(mnemonic: &Mnemonic, wallet_type: WalletType, account_index: u32, network: Network) -> Result<Self, HDWError> {
        
        let account_public_key = Xprv::from_mnemonic(mnemonic)?
                                .derive_from_path(&Self::account_path(&wallet_type, account_index, network))?
                                .get_xpub();
        
        Ok(Self {
            account_public_key,
            wallet_type,
            account_index,
            network
        })
    }


    /**
        Create a watch only wallet from a master private key
    */
    pub fn from_master_private(key: &str, account_index: u32) -> Result<Self, HDWError> {
        let wallet_type = WalletType::from_xkey(key)?;
        let network = WalletType::network_from_xkey(key)?;

        let account_public_key = Xprv::from_str(key)?
                                .derive_from_path(&Self::account_path(&wallet_type, account_index, network))?
                                .get_xpub();

        Ok(Self {
            account_public_key,
            wallet_type,
            account_index,
            network
        })
    }


    /**
        Create a watch only wallet from a master public key
    */
    pub fn from_account_public(key: &str, account_index: u32) -> Result<Self, HDWError> {
        let wallet_type = WalletType::from_xkey(key)?;
        let network = WalletType::network_from_xkey(key)?;
        
        let account_public_key = Xpub::from_str(key)?;

        Ok(Self {
            account_public_key,
            wallet_type,
            account_index,
            network
        })
    }


    /**
        Create the path to the account level given a wallet type and account index.

        Returns a path from the root to account level
    */
    fn account_path(wallet_type: &WalletType, account_index: u32, network: Network) -> Path {
        let mut path = WalletType::path(wallet_type, network);
        path.children.push(ChildOptions::Hardened(account_index));

        path
    }

    /**
        Create the path to the address level given self, change boolean and address index

        Returns a path from the root to address level
    */
    fn address_path(&self, change: bool, address_index: u32) -> Path {
        let mut path = Self::account_path(&self.wallet_type, self.account_index, self.network);
        path.children.push(ChildOptions::Normal(change as u32));
        path.children.push(ChildOptions::Normal(address_index));

        path
    }

    /**
        Takes in an instance of self and an unlocker and checks if the unlocker corresponds to self. 
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