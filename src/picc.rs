// Commands
pub const REQA: u8 = 0x26;
pub const WUPA: u8 = 0x52;
pub const AUTH_KEY_A: u8 = 0x60;
pub const AUTH_KEY_B: u8 = 0x61;
pub const MIFARE_READ: u8 = 0x30;
pub const MIFARE_WRITE: u8 = 0xa0;
pub const MIFARE_DECREMENT: u8 = 0xc0;
pub const MIFARE_INCREMENT: u8 = 0xc1;

// TODO add all commands, in enum

// Cascade levels
pub const SEL_CL1: u8 = 0x93;
pub const SEL_CL2: u8 = 0x95;
pub const SEL_CL3: u8 = 0x97;

// Cascade tag
pub const CT: u8 = 0x88;

pub const MF_ACK: u8 = 0xa;
