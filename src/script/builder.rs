/* 

    Script builder module.

*/

use super::RedeemScript;

#[derive(Debug, Clone)]
pub struct Builder {
    pub code: Vec<u8>
}

impl Builder {
    /// Return a new instance of self
    pub fn new() -> Self  {
        Self { code: Vec::new() }
    }

    /// Push an opcode into self
    pub fn push_opcode(mut self, opcode: Opcode) -> Self {
        self.code.push(opcode.into_u8());
        self
    }

    //Push a slice into the code
    pub fn push_slice(mut self, slice: &[u8]) -> Self {
        self.code.extend_from_slice(slice);
        self
    }

    /// Convert self into a redeem script
    pub fn into_script(self) -> RedeemScript {
        RedeemScript::new(self.code)
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opcode {
    code: u8
}

impl Opcode {
    pub fn into_u8(self) -> u8 {
        self.code
    }
}

impl From<u8> for Opcode {
    fn from(code: u8) -> Self {
        Self { code }
    }
}

// Opcode constants
pub mod opcodes {
    use super::Opcode;

    /// Push an empty array onto the stack
    pub const OP_PUSHBYTES_0: Opcode = Opcode {code: 0x00};
    /// Push the next byte as an array onto the stack
    pub const OP_PUSHBYTES_1: Opcode = Opcode {code: 0x01};
    /// Push the next 2 bytes as an array onto the stack
    pub const OP_PUSHBYTES_2: Opcode = Opcode {code: 0x02};
    /// Push the next 2 bytes as an array onto the stack
    pub const OP_PUSHBYTES_3: Opcode = Opcode {code: 0x03};
    /// Push the next 4 bytes as an array onto the stack
    pub const OP_PUSHBYTES_4: Opcode = Opcode {code: 0x04};
    /// Push the next 5 bytes as an array onto the stack
    pub const OP_PUSHBYTES_5: Opcode = Opcode {code: 0x05};
    /// Push the next 6 bytes as an array onto the stack
    pub const OP_PUSHBYTES_6: Opcode = Opcode {code: 0x06};
    /// Push the next 7 bytes as an array onto the stack
    pub const OP_PUSHBYTES_7: Opcode = Opcode {code: 0x07};
    /// Push the next 8 bytes as an array onto the stack
    pub const OP_PUSHBYTES_8: Opcode = Opcode {code: 0x08};
    /// Push the next 9 bytes as an array onto the stack
    pub const OP_PUSHBYTES_9: Opcode = Opcode {code: 0x09};
    /// Push the next 10 bytes as an array onto the stack
    pub const OP_PUSHBYTES_10: Opcode = Opcode {code: 0x0a};
    /// Push the next 11 bytes as an array onto the stack
    pub const OP_PUSHBYTES_11: Opcode = Opcode {code: 0x0b};
    /// Push the next 12 bytes as an array onto the stack
    pub const OP_PUSHBYTES_12: Opcode = Opcode {code: 0x0c};
    /// Push the next 13 bytes as an array onto the stack
    pub const OP_PUSHBYTES_13: Opcode = Opcode {code: 0x0d};
    /// Push the next 14 bytes as an array onto the stack
    pub const OP_PUSHBYTES_14: Opcode = Opcode {code: 0x0e};
    /// Push the next 15 bytes as an array onto the stack
    pub const OP_PUSHBYTES_15: Opcode = Opcode {code: 0x0f};
    /// Push the next 16 bytes as an array onto the stack
    pub const OP_PUSHBYTES_16: Opcode = Opcode {code: 0x10};
    /// Push the next 17 bytes as an array onto the stack
    pub const OP_PUSHBYTES_17: Opcode = Opcode {code: 0x11};
    /// Push the next 18 bytes as an array onto the stack
    pub const OP_PUSHBYTES_18: Opcode = Opcode {code: 0x12};
    /// Push the next 19 bytes as an array onto the stack
    pub const OP_PUSHBYTES_19: Opcode = Opcode {code: 0x13};
    /// Push the next 20 bytes as an array onto the stack
    pub const OP_PUSHBYTES_20: Opcode = Opcode {code: 0x14};
    /// Push the next 21 bytes as an array onto the stack
    pub const OP_PUSHBYTES_21: Opcode = Opcode {code: 0x15};
    /// Push the next 22 bytes as an array onto the stack
    pub const OP_PUSHBYTES_22: Opcode = Opcode {code: 0x16};
    /// Push the next 23 bytes as an array onto the stack
    pub const OP_PUSHBYTES_23: Opcode = Opcode {code: 0x17};
    /// Push the next 24 bytes as an array onto the stack
    pub const OP_PUSHBYTES_24: Opcode = Opcode {code: 0x18};
    /// Push the next 25 bytes as an array onto the stack
    pub const OP_PUSHBYTES_25: Opcode = Opcode {code: 0x19};
    /// Push the next 26 bytes as an array onto the stack
    pub const OP_PUSHBYTES_26: Opcode = Opcode {code: 0x1a};
    /// Push the next 27 bytes as an array onto the stack
    pub const OP_PUSHBYTES_27: Opcode = Opcode {code: 0x1b};
    /// Push the next 28 bytes as an array onto the stack
    pub const OP_PUSHBYTES_28: Opcode = Opcode {code: 0x1c};
    /// Push the next 29 bytes as an array onto the stack
    pub const OP_PUSHBYTES_29: Opcode = Opcode {code: 0x1d};
    /// Push the next 30 bytes as an array onto the stack
    pub const OP_PUSHBYTES_30: Opcode = Opcode {code: 0x1e};
    /// Push the next 31 bytes as an array onto the stack
    pub const OP_PUSHBYTES_31: Opcode = Opcode {code: 0x1f};
    /// Push the next 32 bytes as an array onto the stack
    pub const OP_PUSHBYTES_32: Opcode = Opcode {code: 0x20};
    /// Push the next 33 bytes as an array onto the stack
    pub const OP_PUSHBYTES_33: Opcode = Opcode {code: 0x21};
    /// Push the next 34 bytes as an array onto the stack
    pub const OP_PUSHBYTES_34: Opcode = Opcode {code: 0x22};
    /// Push the next 35 bytes as an array onto the stack
    pub const OP_PUSHBYTES_35: Opcode = Opcode {code: 0x23};
    /// Push the next 36 bytes as an array onto the stack
    pub const OP_PUSHBYTES_36: Opcode = Opcode {code: 0x24};
    /// Push the next 37 bytes as an array onto the stack
    pub const OP_PUSHBYTES_37: Opcode = Opcode {code: 0x25};
    /// Push the next 38 bytes as an array onto the stack
    pub const OP_PUSHBYTES_38: Opcode = Opcode {code: 0x26};
    /// Push the next 39 bytes as an array onto the stack
    pub const OP_PUSHBYTES_39: Opcode = Opcode {code: 0x27};
    /// Push the next 40 bytes as an array onto the stack
    pub const OP_PUSHBYTES_40: Opcode = Opcode {code: 0x28};
    /// Push the next 41 bytes as an array onto the stack
    pub const OP_PUSHBYTES_41: Opcode = Opcode {code: 0x29};
    /// Push the next 42 bytes as an array onto the stack
    pub const OP_PUSHBYTES_42: Opcode = Opcode {code: 0x2a};
    /// Push the next 43 bytes as an array onto the stack
    pub const OP_PUSHBYTES_43: Opcode = Opcode {code: 0x2b};
    /// Push the next 44 bytes as an array onto the stack
    pub const OP_PUSHBYTES_44: Opcode = Opcode {code: 0x2c};
    /// Push the next 45 bytes as an array onto the stack
    pub const OP_PUSHBYTES_45: Opcode = Opcode {code: 0x2d};
    /// Push the next 46 bytes as an array onto the stack
    pub const OP_PUSHBYTES_46: Opcode = Opcode {code: 0x2e};
    /// Push the next 47 bytes as an array onto the stack
    pub const OP_PUSHBYTES_47: Opcode = Opcode {code: 0x2f};
    /// Push the next 48 bytes as an array onto the stack
    pub const OP_PUSHBYTES_48: Opcode = Opcode {code: 0x30};
    /// Push the next 49 bytes as an array onto the stack
    pub const OP_PUSHBYTES_49: Opcode = Opcode {code: 0x31};
    /// Push the next 50 bytes as an array onto the stack
    pub const OP_PUSHBYTES_50: Opcode = Opcode {code: 0x32};
    /// Push the next 51 bytes as an array onto the stack
    pub const OP_PUSHBYTES_51: Opcode = Opcode {code: 0x33};
    /// Push the next 52 bytes as an array onto the stack
    pub const OP_PUSHBYTES_52: Opcode = Opcode {code: 0x34};
    /// Push the next 53 bytes as an array onto the stack
    pub const OP_PUSHBYTES_53: Opcode = Opcode {code: 0x35};
    /// Push the next 54 bytes as an array onto the stack
    pub const OP_PUSHBYTES_54: Opcode = Opcode {code: 0x36};
    /// Push the next 55 bytes as an array onto the stack
    pub const OP_PUSHBYTES_55: Opcode = Opcode {code: 0x37};
    /// Push the next 56 bytes as an array onto the stack
    pub const OP_PUSHBYTES_56: Opcode = Opcode {code: 0x38};
    /// Push the next 57 bytes as an array onto the stack
    pub const OP_PUSHBYTES_57: Opcode = Opcode {code: 0x39};
    /// Push the next 58 bytes as an array onto the stack
    pub const OP_PUSHBYTES_58: Opcode = Opcode {code: 0x3a};
    /// Push the next 59 bytes as an array onto the stack
    pub const OP_PUSHBYTES_59: Opcode = Opcode {code: 0x3b};
    /// Push the next 60 bytes as an array onto the stack
    pub const OP_PUSHBYTES_60: Opcode = Opcode {code: 0x3c};
    /// Push the next 61 bytes as an array onto the stack
    pub const OP_PUSHBYTES_61: Opcode = Opcode {code: 0x3d};
    /// Push the next 62 bytes as an array onto the stack
    pub const OP_PUSHBYTES_62: Opcode = Opcode {code: 0x3e};
    /// Push the next 63 bytes as an array onto the stack
    pub const OP_PUSHBYTES_63: Opcode = Opcode {code: 0x3f};
    /// Push the next 64 bytes as an array onto the stack
    pub const OP_PUSHBYTES_64: Opcode = Opcode {code: 0x40};
    /// Push the next 65 bytes as an array onto the stack
    pub const OP_PUSHBYTES_65: Opcode = Opcode {code: 0x41};
    /// Push the next 66 bytes as an array onto the stack
    pub const OP_PUSHBYTES_66: Opcode = Opcode {code: 0x42};
    /// Push the next 67 bytes as an array onto the stack
    pub const OP_PUSHBYTES_67: Opcode = Opcode {code: 0x43};
    /// Push the next 68 bytes as an array onto the stack
    pub const OP_PUSHBYTES_68: Opcode = Opcode {code: 0x44};
    /// Push the next 69 bytes as an array onto the stack
    pub const OP_PUSHBYTES_69: Opcode = Opcode {code: 0x45};
    /// Push the next 70 bytes as an array onto the stack
    pub const OP_PUSHBYTES_70: Opcode = Opcode {code: 0x46};
    /// Push the next 71 bytes as an array onto the stack
    pub const OP_PUSHBYTES_71: Opcode = Opcode {code: 0x47};
    /// Push the next 72 bytes as an array onto the stack
    pub const OP_PUSHBYTES_72: Opcode = Opcode {code: 0x48};
    /// Push the next 73 bytes as an array onto the stack
    pub const OP_PUSHBYTES_73: Opcode = Opcode {code: 0x49};
    /// Push the next 74 bytes as an array onto the stack
    pub const OP_PUSHBYTES_74: Opcode = Opcode {code: 0x4a};
    /// Push the next 75 bytes as an array onto the stack
    pub const OP_PUSHBYTES_75: Opcode = Opcode {code: 0x4b};
    /// Read the next byte as N; push the next N bytes as an array onto the stack
    pub const OP_PUSHDATA1: Opcode = Opcode {code: 0x4c};
    /// Read the next 2 bytes as N; push the next N bytes as an array onto the stack
    pub const OP_PUSHDATA2: Opcode = Opcode {code: 0x4d};
    /// Read the next 4 bytes as N; push the next N bytes as an array onto the stack
    pub const OP_PUSHDATA4: Opcode = Opcode {code: 0x4e};
    /// Push the array `0x81` onto the stack
    pub const OP_PUSHNUM_NEG1: Opcode = Opcode {code: 0x4f};
    /// Synonym for OP_RETURN
    pub const OP_RESERVED: Opcode = Opcode {code: 0x50};
    /// Push the array `0x01` onto the stack
    pub const OP_PUSHNUM_1: Opcode = Opcode {code: 0x51};
    /// Push the array `0x02` onto the stack
    pub const OP_PUSHNUM_2: Opcode = Opcode {code: 0x52};
    /// Push the array `0x03` onto the stack
    pub const OP_PUSHNUM_3: Opcode = Opcode {code: 0x53};
    /// Push the array `0x04` onto the stack
    pub const OP_PUSHNUM_4: Opcode = Opcode {code: 0x54};
    /// Push the array `0x05` onto the stack
    pub const OP_PUSHNUM_5: Opcode = Opcode {code: 0x55};
    /// Push the array `0x06` onto the stack
    pub const OP_PUSHNUM_6: Opcode = Opcode {code: 0x56};
    /// Push the array `0x07` onto the stack
    pub const OP_PUSHNUM_7: Opcode = Opcode {code: 0x57};
    /// Push the array `0x08` onto the stack
    pub const OP_PUSHNUM_8: Opcode = Opcode {code: 0x58};
    /// Push the array `0x09` onto the stack
    pub const OP_PUSHNUM_9: Opcode = Opcode {code: 0x59};
    /// Push the array `0x0a` onto the stack
    pub const OP_PUSHNUM_10: Opcode = Opcode {code: 0x5a};
    /// Push the array `0x0b` onto the stack
    pub const OP_PUSHNUM_11: Opcode = Opcode {code: 0x5b};
    /// Push the array `0x0c` onto the stack
    pub const OP_PUSHNUM_12: Opcode = Opcode {code: 0x5c};
    /// Push the array `0x0d` onto the stack
    pub const OP_PUSHNUM_13: Opcode = Opcode {code: 0x5d};
    /// Push the array `0x0e` onto the stack
    pub const OP_PUSHNUM_14: Opcode = Opcode {code: 0x5e};
    /// Push the array `0x0f` onto the stack
    pub const OP_PUSHNUM_15: Opcode = Opcode {code: 0x5f};
    /// Push the array `0x10` onto the stack
    pub const OP_PUSHNUM_16: Opcode = Opcode {code: 0x60};
    /// Does nothing
    pub const OP_NOP: Opcode = Opcode {code: 0x61};
    /// Synonym for OP_RETURN
    pub const OP_VER: Opcode = Opcode {code: 0x62};
    /// Pop and execute the next statements if a nonzero element was popped
    pub const OP_IF: Opcode = Opcode {code: 0x63};
    /// Pop and execute the next statements if a zero element was popped
    pub const OP_NOTIF: Opcode = Opcode {code: 0x64};
    /// Fail the script unconditionally, does not even need to be executed
    pub const OP_VERIF: Opcode = Opcode {code: 0x65};
    /// Fail the script unconditionally, does not even need to be executed
    pub const OP_VERNOTIF: Opcode = Opcode {code: 0x66};
    /// Execute statements if those after the previous OP_IF were not, and vice-versa.
    /// If there is no previous OP_IF, this acts as a RETURN.
    pub const OP_ELSE: Opcode = Opcode {code: 0x67};
    /// Pop and execute the next statements if a zero element was popped
    pub const OP_ENDIF: Opcode = Opcode {code: 0x68};
    /// If the top value is zero or the stack is empty, fail; otherwise, pop the stack
    pub const OP_VERIFY: Opcode = Opcode {code: 0x69};
    /// Fail the script immediately. (Must be executed.)
    pub const OP_RETURN: Opcode = Opcode {code: 0x6a};
    /// Pop one element from the main stack onto the alt stack
    pub const OP_TOALTSTACK: Opcode = Opcode {code: 0x6b};
    /// Pop one element from the alt stack onto the main stack
    pub const OP_FROMALTSTACK: Opcode = Opcode {code: 0x6c};
    /// Drops the top two stack items
    pub const OP_2DROP: Opcode = Opcode {code: 0x6d};
    /// Duplicates the top two stack items as AB -> ABAB
    pub const OP_2DUP: Opcode = Opcode {code: 0x6e};
    /// Duplicates the two three stack items as ABC -> ABCABC
    pub const OP_3DUP: Opcode = Opcode {code: 0x6f};
    /// Copies the two stack items of items two spaces back to
    /// the front, as xxAB -> ABxxAB
    pub const OP_2OVER: Opcode = Opcode {code: 0x70};
    /// Moves the two stack items four spaces back to the front,
    /// as xxxxAB -> ABxxxx
    pub const OP_2ROT: Opcode = Opcode {code: 0x71};
    /// Swaps the top two pairs, as ABCD -> CDAB
    pub const OP_2SWAP: Opcode = Opcode {code: 0x72};
    /// Duplicate the top stack element unless it is zero
    pub const OP_IFDUP: Opcode = Opcode {code: 0x73};
    /// Push the current number of stack items onto the stack
    pub const OP_DEPTH: Opcode = Opcode {code: 0x74};
    /// Drops the top stack item
    pub const OP_DROP: Opcode = Opcode {code: 0x75};
    /// Duplicates the top stack item
    pub const OP_DUP: Opcode = Opcode {code: 0x76};
    /// Drops the second-to-top stack item
    pub const OP_NIP: Opcode = Opcode {code: 0x77};
    /// Copies the second-to-top stack item, as xA -> AxA
    pub const OP_OVER: Opcode = Opcode {code: 0x78};
    /// Pop the top stack element as N. Copy the Nth stack element to the top
    pub const OP_PICK: Opcode = Opcode {code: 0x79};
    /// Pop the top stack element as N. Move the Nth stack element to the top
    pub const OP_ROLL: Opcode = Opcode {code: 0x7a};
    /// Rotate the top three stack items, as [top next1 next2] -> [next2 top next1]
    pub const OP_ROT: Opcode = Opcode {code: 0x7b};
    /// Swap the top two stack items
    pub const OP_SWAP: Opcode = Opcode {code: 0x7c};
    /// Copy the top stack item to before the second item, as [top next] -> [top next top]
    pub const OP_TUCK: Opcode = Opcode {code: 0x7d};
    /// Fail the script unconditionally, does not even need to be executed
    pub const OP_CAT: Opcode = Opcode {code: 0x7e};
    /// Fail the script unconditionally, does not even need to be executed
    pub const OP_SUBSTR: Opcode = Opcode {code: 0x7f};
    /// Fail the script unconditionally, does not even need to be executed
    pub const OP_LEFT: Opcode = Opcode {code: 0x80};
    /// Fail the script unconditionally, does not even need to be executed
    pub const OP_RIGHT: Opcode = Opcode {code: 0x81};
    /// Pushes the length of the top stack item onto the stack
    pub const OP_SIZE: Opcode = Opcode {code: 0x82};
    /// Fail the script unconditionally, does not even need to be executed
    pub const OP_INVERT: Opcode = Opcode {code: 0x83};
    /// Fail the script unconditionally, does not even need to be executed
    pub const OP_AND: Opcode = Opcode {code: 0x84};
    /// Fail the script unconditionally, does not even need to be executed
    pub const OP_OR: Opcode = Opcode {code: 0x85};
    /// Fail the script unconditionally, does not even need to be executed
    pub const OP_XOR: Opcode = Opcode {code: 0x86};
    /// Pushes 1 if the inputs are exactly equal, 0 otherwise
    pub const OP_EQUAL: Opcode = Opcode {code: 0x87};
    /// Returns success if the inputs are exactly equal, failure otherwise
    pub const OP_EQUALVERIFY: Opcode = Opcode {code: 0x88};
    /// Synonym for OP_RETURN
    pub const OP_RESERVED1: Opcode = Opcode {code: 0x89};
    /// Synonym for OP_RETURN
    pub const OP_RESERVED2: Opcode = Opcode {code: 0x8a};
    /// Increment the top stack element in place
    pub const OP_1ADD: Opcode = Opcode {code: 0x8b};
    /// Decrement the top stack element in place
    pub const OP_1SUB: Opcode = Opcode {code: 0x8c};
    /// Fail the script unconditionally, does not even need to be executed
    pub const OP_2MUL: Opcode = Opcode {code: 0x8d};
    /// Fail the script unconditionally, does not even need to be executed
    pub const OP_2DIV: Opcode = Opcode {code: 0x8e};
    /// Multiply the top stack item by -1 in place
    pub const OP_NEGATE: Opcode = Opcode {code: 0x8f};
    /// Absolute value the top stack item in place
    pub const OP_ABS: Opcode = Opcode {code: 0x90};
    /// Map 0 to 1 and everything else to 0, in place
    pub const OP_NOT: Opcode = Opcode {code: 0x91};
    /// Map 0 to 0 and everything else to 1, in place
    pub const OP_0NOTEQUAL: Opcode = Opcode {code: 0x92};
    /// Pop two stack items and push their sum
    pub const OP_ADD: Opcode = Opcode {code: 0x93};
    /// Pop two stack items and push the second minus the top
    pub const OP_SUB: Opcode = Opcode {code: 0x94};
    /// Fail the script unconditionally, does not even need to be executed
    pub const OP_MUL: Opcode = Opcode {code: 0x95};
    /// Fail the script unconditionally, does not even need to be executed
    pub const OP_DIV: Opcode = Opcode {code: 0x96};
    /// Fail the script unconditionally, does not even need to be executed
    pub const OP_MOD: Opcode = Opcode {code: 0x97};
    /// Fail the script unconditionally, does not even need to be executed
    pub const OP_LSHIFT: Opcode = Opcode {code: 0x98};
    /// Fail the script unconditionally, does not even need to be executed
    pub const OP_RSHIFT: Opcode = Opcode {code: 0x99};
    /// Pop the top two stack items and push 1 if both are nonzero, else push 0
    pub const OP_BOOLAND: Opcode = Opcode {code: 0x9a};
    /// Pop the top two stack items and push 1 if either is nonzero, else push 0
    pub const OP_BOOLOR: Opcode = Opcode {code: 0x9b};
    /// Pop the top two stack items and push 1 if both are numerically equal, else push 0
    pub const OP_NUMEQUAL: Opcode = Opcode {code: 0x9c};
    /// Pop the top two stack items and return success if both are numerically equal, else return failure
    pub const OP_NUMEQUALVERIFY: Opcode = Opcode {code: 0x9d};
    /// Pop the top two stack items and push 0 if both are numerically equal, else push 1
    pub const OP_NUMNOTEQUAL: Opcode = Opcode {code: 0x9e};
    /// Pop the top two items; push 1 if the second is less than the top, 0 otherwise
    pub const OP_LESSTHAN : Opcode = Opcode {code: 0x9f};
    /// Pop the top two items; push 1 if the second is greater than the top, 0 otherwise
    pub const OP_GREATERTHAN : Opcode = Opcode {code: 0xa0};
    /// Pop the top two items; push 1 if the second is <= the top, 0 otherwise
    pub const OP_LESSTHANOREQUAL : Opcode = Opcode {code: 0xa1};
    /// Pop the top two items; push 1 if the second is >= the top, 0 otherwise
    pub const OP_GREATERTHANOREQUAL : Opcode = Opcode {code: 0xa2};
    /// Pop the top two items; push the smaller
    pub const OP_MIN: Opcode = Opcode {code: 0xa3};
    /// Pop the top two items; push the larger
    pub const OP_MAX: Opcode = Opcode {code: 0xa4};
    /// Pop the top three items; if the top is >= the second and < the third, push 1, otherwise push 0
    pub const OP_WITHIN: Opcode = Opcode {code: 0xa5};
    /// Pop the top stack item and push its RIPEMD160 hash
    pub const OP_RIPEMD160: Opcode = Opcode {code: 0xa6};
    /// Pop the top stack item and push its SHA1 hash
    pub const OP_SHA1: Opcode = Opcode {code: 0xa7};
    /// Pop the top stack item and push its SHA256 hash
    pub const OP_SHA256: Opcode = Opcode {code: 0xa8};
    /// Pop the top stack item and push its RIPEMD(SHA256) hash
    pub const OP_HASH160: Opcode = Opcode {code: 0xa9};
    /// Pop the top stack item and push its SHA256(SHA256) hash
    pub const OP_HASH256: Opcode = Opcode {code: 0xaa};
    /// Ignore this and everything preceding when deciding what to sign when signature-checking
    pub const OP_CODESEPARATOR: Opcode = Opcode {code: 0xab};
    /// <https://en.bitcoin.it/wiki/OP_CHECKSIG> pushing 1/0 for success/failure
    pub const OP_CHECKSIG: Opcode = Opcode {code: 0xac};
    /// <https://en.bitcoin.it/wiki/OP_CHECKSIG> returning success/failure
    pub const OP_CHECKSIGVERIFY: Opcode = Opcode {code: 0xad};
    /// Pop N, N pubkeys, M, M signatures, a dummy (due to bug in reference code), and verify that all M signatures are valid.
    /// Push 1 for "all valid", 0 otherwise
    pub const OP_CHECKMULTISIG: Opcode = Opcode {code: 0xae};
    /// Like the above but return success/failure
    pub const OP_CHECKMULTISIGVERIFY: Opcode = Opcode {code: 0xaf};
    /// Does nothing
    pub const OP_NOP1: Opcode = Opcode {code: 0xb0};
    /// <https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki>
    pub const OP_CLTV: Opcode = Opcode {code: 0xb1};
    /// <https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki>
    pub const OP_CSV: Opcode = Opcode {code: 0xb2};
    /// Does nothing
    pub const OP_NOP4: Opcode = Opcode {code: 0xb3};
    /// Does nothing
    pub const OP_NOP5: Opcode = Opcode {code: 0xb4};
    /// Does nothing
    pub const OP_NOP6: Opcode = Opcode {code: 0xb5};
    /// Does nothing
    pub const OP_NOP7: Opcode = Opcode {code: 0xb6};
    /// Does nothing
    pub const OP_NOP8: Opcode = Opcode {code: 0xb7};
    /// Does nothing
    pub const OP_NOP9: Opcode = Opcode {code: 0xb8};
    /// Does nothing
    pub const OP_NOP10: Opcode = Opcode {code: 0xb9};
    // Every other opcode acts as OP_RETURN
    /// OP_CHECKSIGADD post tapscript
    pub const OP_CHECKSIGADD: Opcode = Opcode {code: 0xba};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_187: Opcode = Opcode {code: 0xbb};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_188: Opcode = Opcode {code: 0xbc};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_189: Opcode = Opcode {code: 0xbd};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_190: Opcode = Opcode {code: 0xbe};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_191: Opcode = Opcode {code: 0xbf};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_192: Opcode = Opcode {code: 0xc0};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_193: Opcode = Opcode {code: 0xc1};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_194: Opcode = Opcode {code: 0xc2};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_195: Opcode = Opcode {code: 0xc3};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_196: Opcode = Opcode {code: 0xc4};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_197: Opcode = Opcode {code: 0xc5};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_198: Opcode = Opcode {code: 0xc6};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_199: Opcode = Opcode {code: 0xc7};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_200: Opcode = Opcode {code: 0xc8};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_201: Opcode = Opcode {code: 0xc9};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_202: Opcode = Opcode {code: 0xca};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_203: Opcode = Opcode {code: 0xcb};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_204: Opcode = Opcode {code: 0xcc};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_205: Opcode = Opcode {code: 0xcd};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_206: Opcode = Opcode {code: 0xce};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_207: Opcode = Opcode {code: 0xcf};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_208: Opcode = Opcode {code: 0xd0};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_209: Opcode = Opcode {code: 0xd1};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_210: Opcode = Opcode {code: 0xd2};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_211: Opcode = Opcode {code: 0xd3};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_212: Opcode = Opcode {code: 0xd4};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_213: Opcode = Opcode {code: 0xd5};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_214: Opcode = Opcode {code: 0xd6};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_215: Opcode = Opcode {code: 0xd7};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_216: Opcode = Opcode {code: 0xd8};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_217: Opcode = Opcode {code: 0xd9};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_218: Opcode = Opcode {code: 0xda};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_219: Opcode = Opcode {code: 0xdb};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_220: Opcode = Opcode {code: 0xdc};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_221: Opcode = Opcode {code: 0xdd};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_222: Opcode = Opcode {code: 0xde};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_223: Opcode = Opcode {code: 0xdf};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_224: Opcode = Opcode {code: 0xe0};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_225: Opcode = Opcode {code: 0xe1};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_226: Opcode = Opcode {code: 0xe2};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_227: Opcode = Opcode {code: 0xe3};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_228: Opcode = Opcode {code: 0xe4};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_229: Opcode = Opcode {code: 0xe5};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_230: Opcode = Opcode {code: 0xe6};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_231: Opcode = Opcode {code: 0xe7};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_232: Opcode = Opcode {code: 0xe8};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_233: Opcode = Opcode {code: 0xe9};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_234: Opcode = Opcode {code: 0xea};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_235: Opcode = Opcode {code: 0xeb};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_236: Opcode = Opcode {code: 0xec};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_237: Opcode = Opcode {code: 0xed};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_238: Opcode = Opcode {code: 0xee};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_239: Opcode = Opcode {code: 0xef};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_240: Opcode = Opcode {code: 0xf0};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_241: Opcode = Opcode {code: 0xf1};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_242: Opcode = Opcode {code: 0xf2};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_243: Opcode = Opcode {code: 0xf3};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_244: Opcode = Opcode {code: 0xf4};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_245: Opcode = Opcode {code: 0xf5};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_246: Opcode = Opcode {code: 0xf6};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_247: Opcode = Opcode {code: 0xf7};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_248: Opcode = Opcode {code: 0xf8};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_249: Opcode = Opcode {code: 0xf9};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_250: Opcode = Opcode {code: 0xfa};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_251: Opcode = Opcode {code: 0xfb};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_252: Opcode = Opcode {code: 0xfc};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_253: Opcode = Opcode {code: 0xfd};
    /// Synonym for OP_RETURN
    pub const OP_RETURN_254: Opcode = Opcode {code: 0xfe};
    /// Synonym for OP_RETURN
    pub const OP_INVALIDOPCODE: Opcode = Opcode {code: 0xff};
}