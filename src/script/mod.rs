/*
    Script module that implements necessary scripts for creating addresses and
    redeem scripts.
*/

pub mod builder;
pub mod redeem_script;
pub mod witness_program;

pub use builder::Builder as ScriptBuilder;
pub use builder::opcodes as opcodes;
pub use builder::Opcode as Opcode;
pub use redeem_script::RedeemScript as RedeemScript;
pub use witness_program::WitnessProgram as WitnessProgram;

#[derive(Debug)]
pub enum ScriptErr {
    BadNetwork(),
    KeyCountDoesNotMatch(),
    MaxKeyCountExceeded(),
    HashLenIncorrect(usize),
    BadVersion(u8)
}