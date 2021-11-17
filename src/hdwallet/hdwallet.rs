/*
    Implementation of a PKH HD Wallet following
    BIP-32, BIP-44, BIP-49 and BIP-84.

    Custom derivation paths are also supported but require
    external path management.

    Todo:
        - Write unit tests for:
            > Custom path cases
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
    P2SH_P2WPKH,
    P2TR
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
            WalletType::P2TR => match network {
                Network::Bitcoin => VersionPrefix::Xpub,
                Network::Testnet => VersionPrefix::Tpub
            }
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
            WalletType::P2TR => match network {
                Network::Bitcoin => VersionPrefix::Xprv,
                Network::Testnet => VersionPrefix::Tprv
            }
        }
    }

    fn get_version_prefix(&self, network: Network) -> (VersionPrefix, VersionPrefix) {
        match &self {
            WalletType::P2PKH => match network {
                Network::Bitcoin => (VersionPrefix::Xpub, VersionPrefix::Xprv),
                Network::Testnet => (VersionPrefix::Tpub, VersionPrefix::Tprv)
            },
            WalletType::P2SH_P2WPKH => match network {
                Network::Bitcoin => (VersionPrefix::Ypub, VersionPrefix::Yprv),
                Network::Testnet => (VersionPrefix::Upub, VersionPrefix::Uprv)
            },
            WalletType::P2WPKH => match network {
                Network::Bitcoin => (VersionPrefix::Zpub, VersionPrefix::Zprv),
                Network::Testnet => (VersionPrefix::Vpub, VersionPrefix::Vprv)
            },
            WalletType::P2TR => match network {
                Network::Bitcoin => (VersionPrefix::Xpub, VersionPrefix::Xprv),
                Network::Testnet => (VersionPrefix::Tpub, VersionPrefix::Tprv)
            }
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
            WalletType::P2TR => Path::from_str("m/86'").unwrap()
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
    pub fn set_type(&mut self, wallet_type: WalletType) -> Result<(), HDWError> {
        if self.wallet_type.is_some() && self.wallet_type.unwrap() != wallet_type {
            return Err(HDWError::TypeDiscrepancy)
        }
        
        self.wallet_type = Some(wallet_type);
        Ok(())
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

impl HDStandardPathing for HDWallet { }
impl HDWallet {
    /**
        Takes in an instance of self and an unlocker and checks if the unlocker corresponds to self. 

        Update to use StandardPathing trait
    */
    fn unlock(&self, unlocker: &Unlocker) -> Result<(), HDWError> {
        //If the account key derived from the unlocker is equal to the stored account key,
        //return the master private key in the unlocker.
        let derived_account_key = unlocker.master_private_key
                                    .derive_from_path(&self.derivation)?
                                    .get_xpub()
                                    .key::<33>();

        if derived_account_key == self.account_public_key().key::<33>() {
            return Ok(())
        }

        Err(HDWError::BadKey())
    }
    
    //Return the master private key of the wallet given a valid unlocker
    pub fn master_private_key(&self, unlocker: &Unlocker) -> Result<Xprv, HDWError> {
        self.unlock(unlocker)?;
        
        Ok(unlocker.master_private_key.clone())
    }


    //Return the master public key of the wallet given a valid unlocker
    pub fn master_public_key(&self, unlocker: &Unlocker) -> Result<Xpub, HDWError> {
        Ok(self.master_private_key(unlocker)?.get_xpub())
    }

    
    //Return the share level private key given a valid unlocker
    pub fn account_private_key(&self, unlocker: &Unlocker) -> Result<Xprv, HDWError> {
        self.unlock(unlocker)?;
        Ok(
            unlocker.master_private_key
                .derive_from_path(&self.derivation)?
        )                          
    }

    //return the share level public key.
    //This is the highest order key stored in the struct
    pub fn account_public_key(&self) -> Xpub {
        self.account_public_key.clone()
    }

    
    //Return the private key at an address given a valid unlocker
    pub fn address_private_key(&self, change: bool, address_index: u32, unlocker: &Unlocker) -> Result<PrivKey, HDWError> {
        self.unlock(unlocker)?;
        
        let path = Self::to_address_from_shared(change, address_index);
        
        Ok(
            PrivKey::from_slice(
                &self.account_private_key(unlocker)?.derive_from_path(&path)?.key::<32>()
            ).unwrap()
        )
    }

    //Return the public key at an address
    pub fn address_public_key(&self, change: bool, address_index: u32) -> Result<PubKey, HDWError> {
        //Deriving path working from the account level
        let mut path: Path = Path::empty();
        path.children.push(ChildOptions::Normal(change as u32));
        path.children.push(ChildOptions::Normal(address_index));

        Ok(
            self.account_public_key().derive_from_path(&path)?.get_pub()
        )
    }

    //Return an address
    pub fn address_at(
        &self,
        change: bool,
        address_index: u32
    ) -> Result<String, HDWError> {
        //Deriving path working from the account level
        let mut p: Path = Path::empty();
        p.children.push(ChildOptions::Normal(change as u32));
        p.children.push(ChildOptions::Normal(address_index));

        let address = self.account_public_key.derive_from_path(&p)?.get_address(&self.wallet_type, self.network);

        Ok(address)
    }
}


#[cfg(test)]
mod tests {
    use crate::bip39::Language;

    use super::*;

    #[test]
    fn good_segwit_hd_wallet() -> Result<(), HDWError> {
        let mut wallets = vec![];
        wallets.push( segwit_from_mnemonic()? );
        wallets.push( segwit_from_master()? );
        wallets.push( segwit_from_shared()? );

        for wallet in wallets {
            //Compare addresses
            assert_eq!(wallet.address_at(false, 0)?, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
            assert_eq!(wallet.address_at(true, 0)?, "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
        }

        Ok(())
    }

    fn segwit_from_mnemonic() -> Result<HDWallet, HDWError> {
        let mut b = HDWalletBuilder::new();
        let mnemonic = Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(), Language::English, "").unwrap();
        b.set_signer_from_mnemonic(&mnemonic)?;
        Ok(b.build()?)
    }

    fn segwit_from_master() -> Result<HDWallet, HDWError> {
        let mut b = HDWalletBuilder::new();
        b.set_signer_from_xprv("zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5")?;
        Ok(b.build()?)
    }

    fn segwit_from_shared() -> Result<HDWallet, HDWError> {
        let mut b = HDWalletBuilder::new();
        b.set_signer_from_xpub("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")?;
        Ok(b.build()?)
    }

    #[test]
    fn good_nested_segwit_hd_wallet() -> Result<(), HDWError> {
        let mut wallets = vec![];
        wallets.push( nested_segwit_from_mnemonic()? );
        wallets.push( nested_segwit_from_master()?  );
        wallets.push( nested_segwit_from_shared()? );

        for wallet in wallets {
            //Compare addresses
            assert_eq!(wallet.address_at(false, 0)?, "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf");
            assert_eq!(wallet.address_at(true, 0)?, "34K56kSjgUCUSD8GTtuF7c9Zzwokbs6uZ7");
        }


        Ok(())
    }

    fn nested_segwit_from_mnemonic() -> Result<HDWallet, HDWError> {
        let mut b = HDWalletBuilder::new();
        let mnemonic = Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(), Language::English, "").unwrap();
        b.set_signer_from_mnemonic(&mnemonic)?;
        b.set_type(WalletType::P2SH_P2WPKH).unwrap();
        Ok(b.build()?)
    }

    fn nested_segwit_from_master() -> Result<HDWallet, HDWError> {
        let mut b = HDWalletBuilder::new();
        b.set_signer_from_xprv("yprvABrGsX5C9jantZVwdwcQhDXkqsu4RoSAZKBwPnLA3uyeVM3C3fvTuqzru4fovMSLqYSqALGe9MBqCf7Pg7Y7CTsjoNnLYg6HxR2Xo44NX7E")?;
        Ok(b.build()?)
    }

    fn nested_segwit_from_shared() -> Result<HDWallet, HDWError> {
        let mut b = HDWalletBuilder::new();
        b.set_signer_from_xpub("ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP")?;
        Ok(b.build()?)
    }

    #[test]
    fn good_legacy_hd_wallet() -> Result<(), HDWError> {
        let mut wallets = vec![];
        wallets.push( legacy_from_mnemonic()? );
        wallets.push( legacy_from_master()?  );
        wallets.push( legacy_from_shared()? );

        for wallet in wallets {
            //Compare addresses
            assert_eq!(wallet.address_at(false, 0)?, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");
            assert_eq!(wallet.address_at(true, 0)?, "1J3J6EvPrv8q6AC3VCjWV45Uf3nssNMRtH");
        }

        Ok(())
    }

    fn legacy_from_mnemonic() -> Result<HDWallet, HDWError> {
        let mut b = HDWalletBuilder::new();
        let mnemonic = Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(), Language::English, "").unwrap();
        b.set_signer_from_mnemonic(&mnemonic)?;
        b.set_type(WalletType::P2PKH).unwrap();
        Ok(b.build()?)
    }

    fn legacy_from_master() -> Result<HDWallet, HDWError> {
        let mut b = HDWalletBuilder::new();
        b.set_signer_from_xprv("xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu")?;
        Ok(b.build()?)
    }

    fn legacy_from_shared() -> Result<HDWallet, HDWError> {
        let mut b = HDWalletBuilder::new();
        b.set_signer_from_xpub("xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj")?;
        Ok(b.build()?)
    }

    //Testing cases where the wallet builder fails
    #[test]
    fn builder_fail_cases() {
        let zprv = "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5";
        let xpub = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj";
        let ypub = "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP";
        let zpub = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

        //No keys provided
        {
            let b = HDWalletBuilder::new();
            assert!( match_fail_case(b, HDWError::MissingFields) );
        }

        //Two keys provided
        {
            let mut b = HDWalletBuilder::new();
            b.set_signer_from_xprv(zprv).unwrap();
            b.set_signer_from_xpub(zpub).unwrap();
            assert!( match_fail_case(b, HDWError::BadKey()) );
        }

        //Type discrepancy
        {
            let keys = vec![        xpub,                ypub,                  zpub       ];
            let types = vec![WalletType::P2WPKH, WalletType::P2PKH, WalletType::P2SH_P2WPKH];

            for i in 0..3 {
                let mut b = HDWalletBuilder::new();
                b.set_type( types[i] ).unwrap();
                match b.set_signer_from_xpub(keys[i]) {
                    Ok(_) => assert!(false),
                    Err(x) => assert_eq!(x, HDWError::TypeDiscrepancy)
                }
            }
        }
    }

    fn match_fail_case(b: HDWalletBuilder, expected_err: HDWError) -> bool {
        match b.build() {
            Ok(_) => false,
            Err(x) => x==expected_err
        }
    }

    #[test]
    fn bip_86_test_vectors() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English, "").unwrap();
        
        //Build wallet
        let mut builder = HDWalletBuilder::new();
        builder.set_signer_from_mnemonic(&mnemonic).unwrap();
        builder.set_type(WalletType::P2TR).unwrap();
        let wallet = builder.build().unwrap();

        //First receiving address
        let address = wallet.address_at(false, 0).unwrap();
        assert_eq!(address, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");

        //Second receiving address
        let address = wallet.address_at(false, 1).unwrap();
        assert_eq!(address, "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh");

        //First change address
        let address = wallet.address_at(true, 0).unwrap();
        assert_eq!(address, "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7");

    }
}