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
    hash,
    util::try_into,
    util::Network
};


pub struct HDWallet {
    pub mnemonic: Mnemonic,
    mpriv_key: Xprv
}



impl HDWallet {
    /**
        Creates a new HD Wallet structure from mnemonic
    */
    pub fn new(mnemonic: Mnemonic) -> Result<Self, HDWError> {
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
            mpriv_key
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
    fn get_addresses(&self, path: &str, count: usize, segwit: bool, network: Network) -> Result<Vec<String>, HDWError> {
        let mut addresses: Vec<String> = vec![];
        let mut p: Path = Path::from_str(path)?;
        let last_index = p.children.len()-1;
        for _i in 0..count {
            //Push the address at the current path into the return vec
            if segwit {
                addresses.push(self.mpriv_key().derive_from_path(&p)?.get_bech32_address(network.clone()));
            } else {
                addresses.push(self.mpriv_key().derive_from_path(&p)?.get_legacy_address(network.clone()));
            }
            
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

    /**
        Return legacy addresses at a given deriveration path
    */
    pub fn get_legacy_addresses(&self, path: &str, count: usize, network: Network)  -> Result<Vec<String>, HDWError> {
        Self::get_addresses(self, path, count, false, network)
    }

    /**
        Return segwit addresses at a given deriveration path
    */
    pub fn get_bech32_addresses(&self, path: &str, count: usize, network: Network) -> Result<Vec<String>, HDWError> {
        Self::get_addresses(self, path, count, true, network)
    }

}