use crate::{
    util::Network
};

#[derive(Debug, Clone, Copy)]
pub enum VersionPrefix {
    //One byte version prefixes
        BTCAddress = 0x00,
        BTCTestNetAddress = 0x6F,
        P2ScriptAddress = 0x05,
        TestnetP2SHAddress = 0xC4,
        PrivateKeyWIF = 0x80,
        TestNetPrivateKeyWIF = 0xef,
    
    //Four byte version prefixes
        //BIP-32
        Xprv = 0x0488ADE4, //Legacy P2PKH
        Xpub = 0x0488B21E,
        Tprv = 0x04358394,
        Tpub = 0x043587CF,
        //BIP-49
        Yprv = 0x049d7878, //P2SH nested P2WPKH
        Ypub = 0x049d7cb2,
        Uprv = 0x044a4e28,
        Upub = 0x044a5262,
        //BIP-84
        Zprv = 0x04b2430c, //P2WPKH
        Zpub = 0x04b24746,
        Vprv = 0x045f18bc,
        Vpub = 0x045f1cf6,

        //SLIP-0132
        SLIP132Ypub = 0x0295b43f, //Multi-signature P2WSH in P2SH
        SLIP132Yprv = 0x0295b005,
        SLIP132Zpub = 0x02aa7ed3, //Multi-signature P2WSH
        SLIP132Zprv = 0x02aa7a99,
        SLIP132Upub = 0x024289ef, //Multi-signature P2WSH in P2SH Testnet
        SLIP132Uprv = 0x024285b5,
        SLIP132Vpub = 0x02575483, //Multi-signature P2WSH Testnet
        SLIP132Vprv = 0x02575048,

    //No data
        None
}

impl VersionPrefix {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            //Special cases where version bytes is not 4 bytes long
            VersionPrefix::BTCAddress => vec![0x00],
            VersionPrefix::BTCTestNetAddress => vec![0x6F],
            VersionPrefix::P2ScriptAddress => vec![0x05],
            VersionPrefix::TestnetP2SHAddress => vec![0xC4],
            VersionPrefix::PrivateKeyWIF => vec![0x80],
            VersionPrefix::TestNetPrivateKeyWIF => vec![0xef],
            VersionPrefix::None => vec![],
            
            //Cases where version bytes is 4 bytes long
            _ => (*self as u32).to_be_bytes().to_vec()
        }
    }

    pub fn from_int(int: u32) -> Result<Self, ()> {
        Ok(match int {
            0x00 => Self::BTCAddress,
            0x6F => Self::BTCTestNetAddress,
            0x05 => Self::P2ScriptAddress,
            0xC4 => Self::TestnetP2SHAddress,
            0x80 => Self::PrivateKeyWIF,
            0xEF => Self:: TestNetPrivateKeyWIF,
            0x0488ADE4 => Self::Xprv,
            0x0488B21E => Self::Xpub,
            0x04358394 => Self::Tprv,
            0x043587cf => Self::Tpub,
            0x049d7878 => Self::Yprv,
            0x049d7cb2 => Self::Ypub,
            0x044a4e28 => Self::Uprv,
            0x044a5262 => Self::Upub,
            0x04b2430c => Self::Zprv,
            0x04b24746 => Self::Zpub,
            0x045f18bc => Self::Vprv,
            0x045f1cf6 => Self::Vpub,
            0x0295b43f => Self::SLIP132Ypub,
            0x0295b005 => Self::SLIP132Yprv,
            0x02aa7ed3 => Self::SLIP132Zpub,
            0x02aa7a99 => Self::SLIP132Zprv,
            0x024289ef => Self::SLIP132Upub,
            0x024285b5 => Self::SLIP132Uprv,
            0x02575483 => Self::SLIP132Vpub,
            0x02575048 => Self::SLIP132Vprv,
            
            _ => return Err(())
        })
    }
}

pub trait ToVersionPrefix {
    fn public_version_prefix(&self, network: Network) -> VersionPrefix;
    fn private_version_prefix(&self, network: Network) -> VersionPrefix;
    fn get_version_prefix(&self, network: Network) -> (VersionPrefix, VersionPrefix);
}