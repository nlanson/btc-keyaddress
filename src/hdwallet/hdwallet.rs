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
    hash,
    util::try_into,
    util::Network
};


pub struct HDWallet {
    pub mnemonic: Mnemonic,
    mpriv_key: Xprv,
    r#type: WalletType
}


#[derive(Clone)]
pub enum WalletType {
    P2PKH,
    P2WPKH,
    P2SH_P2WPKH
}

impl WalletType {
    pub fn from_xkey(key: &str) -> Result<Self, ()> {
        let bytes = match decode(&key.to_string()) {
            Ok(x) => x,
            Err(_) => return Err(())
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
            _ => return Err(())
        }
    }

    pub fn path(&self) -> Path {
        match &self {
            WalletType::P2PKH => Path::from_str("m/44'/0'").unwrap(),
            WalletType::P2WPKH => Path::from_str("m/84'/0'").unwrap(),
            WalletType::P2SH_P2WPKH => Path::from_str("m/49'/0'").unwrap()

        }
    }
}


impl HDWallet {
    /**
        Creates a new HD Wallet structure from mnemonic
    */
    pub fn new(mnemonic: Mnemonic, r#type: WalletType) -> Result<Self, HDWError> {
        let mprivkey_bytes: [u8; 64] = hash::hmac_sha512(&mnemonic.seed(), b"Bitcoin seed");
        let mpriv_key: Xprv = Xprv::construct(
        match PrivKey::from_slice(&mprivkey_bytes[0..32]) {
                Ok(x) => x,
                Err(_) => return Err(HDWError::BadKey())
            },
        try_into(mprivkey_bytes[32..64].to_vec()),
        0x00,
        [0x00; 4],
        [0x00; 4]
        );

        Ok(Self {
            mnemonic,
            mpriv_key,
            r#type
        })
    }

    /**
        Returns the stored extended master private key. Wrapped in a method for consistency.
    */
    pub fn mpriv_key(&self) -> Xprv {
        self.mpriv_key.clone()
    }

    /**
        Get the master extended public key derived from the master extended private key
    */
    pub fn mpub_key(&self) -> Xpub {
        self.mpriv_key().get_xpub()
    }

    /**
        Wrapper function to get the extended key pair at specified path.
    */
    pub fn get_xprv_key_at(&self, path: &str) -> Result<Xprv, HDWError> {
        
        let p: Path  = Path::from_str(path)?;

        let xprv: Xprv = match self.mpriv_key().derive_from_path(&p) {
            Ok(x) => x,
            Err(x) => match x {
                HDWError::BadPath(_) => return Err(HDWError::BadPath(path.to_string())),
                _ => return Err(x)
            }
        };

        Ok(xprv)
    }

    /**
        Creates a lists of addresses at a given path
    */
    pub fn get_addresses(&self, path: &str, count: usize, network: Network) -> Result<Vec<String>, HDWError> {
        let mut addresses: Vec<String> = vec![];
        let mut p: Path = Path::from_str(path)?;
        let last_index = p.children.len()-1;
        for _i in 0..count {
            addresses.push(self.mpriv_key().derive_from_path(&p)?.get_address(&self.r#type, network.clone()));
            
            //Then increment the deepest index by one
            match p.children[last_index] {
                ChildOptions::Normal(x) => {
                    let n = x + 1;
                    if n >= (2 as u32).pow(31) { return Err(HDWError::IndexTooLarge(n)) }
                    p.children[last_index] = ChildOptions::Normal(n);
                },
                ChildOptions::Hardened(x) => {
                    let n = x + 1;
                    if n >= (2 as u32).pow(32) { return Err(HDWError::IndexTooLarge(n)) }
                    p.children[last_index] = ChildOptions::Hardened(n);
                }
            }
        }

        Ok(addresses)
    }

}


//New and revised HD Wallet struct from below



pub struct HDWallet2 {
    master_public_key: Option<Xpub>,
    account_public_key: Xpub,
    pub wallet_type: WalletType,
    account_index: u32
}

pub trait WatchOnly<T> {
    /**
        Return a list of addresses at the given deriveration path.
    */
    fn address_at(
        &self,
        change: bool,
        address_index: u32,
        network: Network
    ) -> Result<String, HDWError>
    where Self: Sized;
}

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

impl HDWallet2 {
    /**
        Create a watch only wallet from mnemonic phrase
    */
    pub fn from_mnemonic(mnemonic: &Mnemonic, wallet_type: WalletType, account_index: u32) -> Result<Self, HDWError> {
        let master_public_key = Some(Xpub::from_mnemonic(mnemonic)?);
        
        let account_public_key = Xprv::from_mnemonic(mnemonic)?
                                .derive_from_path(&Self::account_path(&wallet_type, account_index))?
                                .get_xpub();
        
        Ok(Self {
            master_public_key,
            account_public_key,
            wallet_type,
            account_index
        })
    }


    /**
        Create a watch only wallet from a master private key
    */
    pub fn from_master_private(key: &str, account_index: u32) -> Result<Self, HDWError> {
        let wallet_type = match WalletType::from_xkey(key) {
            Ok(x) => x,
            Err(_) => return Err(HDWError::BadKey())
        };

        let master_public_key = Xprv::from_str(key)?.get_xpub();
        let account_public_key = Xprv::from_str(key)?
                                .derive_from_path(&Self::account_path(&wallet_type, account_index))?
                                .get_xpub();

        Ok(Self {
            master_public_key: Some(master_public_key),
            account_public_key,
            wallet_type,
            account_index
        })
    }


    /**
        Create a watch only wallet from a master public key
    */
    pub fn from_master_public(key: &str, account_index: u32) -> Result<Self, HDWError> {
        let wallet_type = match WalletType::from_xkey(key) {
            Ok(x) => x,
            Err(_) => return Err(HDWError::BadKey())
        };

        let account_public_key = Xpub::from_str(key)?;

        Ok(Self {
            master_public_key: None,
            account_public_key,
            wallet_type,
            account_index
        })
    }


    /**
        Create the path to the account level given a wallet type and account index.
    */
    fn account_path(wallet_type: &WalletType, account_index: u32) -> Path {
        let mut path = WalletType::path(wallet_type);
        path.children.push(ChildOptions::Hardened(account_index));

        path
    }

    /**
        Create the path to the address level given self, change boolean and address index
    */
    fn address_path(&self, change: bool, address_index: u32) -> Path {
        let mut path = Self::account_path(&self.wallet_type, self.account_index);
        path.children.push(ChildOptions::Normal(change as u32));
        path.children.push(ChildOptions::Normal(address_index));

        path
    }

    /**
        Return the master private key of self given a valid unlocker 
    */
    pub fn master_private_key(&self, unlocker: &Unlocker) -> Result<Xprv, HDWError> {
        //If the account key derived from the unlocker is equal to the stored account key,
        //return the master private key in the unlocker.
        let derived_account_key = unlocker.master_private_key
                                    .derive_from_path(&Self::account_path(&self.wallet_type, self.account_index))?
                                    .get_xpub()
                                    .key::<33>();

        if derived_account_key == self.account_public_key().key::<33>() {
            return Ok(unlocker.master_private_key.clone())
        }

        
        //If no match, return an error
        Err(HDWError::BadKey())
    }


    /**
        Return the master public key of self 
    */
    pub fn master_public_key(&self) -> Result<Xpub, HDWError> {
        match &self.master_public_key {
            Some(x) => Ok(x.clone()),
            _ => Err(HDWError::WatchOnly)
        }
    }


    /**
        Returns the extended private key for the account level
    */
    pub fn account_private_key(&self, unlocker: &Unlocker) -> Result<Xprv, HDWError> {
        Ok(
            unlocker.master_private_key
                .derive_from_path(&Self::account_path(&self.wallet_type, self.account_index))?
        )                          
    }


    /**
        Return the account level extended public key.
        
        This can be used to import the wallet as watch only
    */
    pub fn account_public_key(&self) -> Xpub {
        self.account_public_key.clone()
    }


    /**
        Return the private key at the given deriveration path given a valid unlocker
    */
    pub fn private_key_at(&self, change: bool, address_index: u32, unlocker: &Unlocker) -> Result<PrivKey, HDWError> {
        let path = self.address_path(change, address_index);
        
        Ok(
            PrivKey::from_slice(
                &self.master_private_key(unlocker)?.derive_from_path(&path)?.key::<32>()
            ).unwrap()
        )
    }


    /**
        Returns the public key at address level given a change boolean and address index
    */
    pub fn public_key_at(&self, change: bool, address_index: u32) -> Result<PubKey, HDWError> {
        //Deriving path working from the account level
        let mut path: Path = Path::empty();
        path.children.push(ChildOptions::Normal(change as u32));
        path.children.push(ChildOptions::Normal(address_index));

        Ok(
            self.account_public_key().derive_from_path(&path)?.get_pub()
        )
    }
}

impl WatchOnly<Unlocker> for HDWallet2 {
    fn address_at(
        &self,
        change: bool,
        address_index: u32,
        network: Network,
    ) -> Result<String, HDWError>
    where Self: Sized
    {
        //Deriving path working from the account level
        let mut p: Path = Path::empty();
        p.children.push(ChildOptions::Normal(change as u32));
        p.children.push(ChildOptions::Normal(address_index));

        let address = self.account_public_key.derive_from_path(&p)?.get_address(&self.wallet_type, network.clone());

        Ok(address)
    }
}