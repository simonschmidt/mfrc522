// Commands
pub const REQA: u8 = 0x26;
pub const WUPA: u8 = 0x52;
pub const AUTH_KEY_A: u8 = 0x60;
pub const AUTH_KEY_B: u8 = 0x61;
pub const MIFARE_READ: u8 = 0x30;

// TODO add all commands, in enum

// Cascade levels
pub const SEL_CL1: u8 = 0x93;
pub const SEL_CL2: u8 = 0x95;
pub const SEL_CL3: u8 = 0x97;

// Cascade tag
pub const CT: u8 = 0x88;



    // Types from https://github.com/miguelbalboa/rfid/
    #[derive(Debug)]
    pub enum Type {
        NotComplete, // UID not complete
        MifareMini,
        Mifare1K,
        Mifare4K,
        MifareUL,
        MifarePlus,
        TNP3XXX,
        ISO1443_4,
        ISO18092,
        Unknown,
    }

    impl Type {
        pub fn from_sak(sak: u8) -> Type {
            match sak {
                0x04 => Type::NotComplete,
                0x09 => Type::MifareMini,
                0x08 => Type::Mifare1K,
                0x18 => Type::Mifare4K,
                0x00 => Type::MifareUL,
                0x10 => Type::MifarePlus,
                0x11 => Type::MifarePlus,
                0x01 => Type::TNP3XXX,
                0x20 => Type::ISO1443_4,
                0x40 => Type::ISO18092,
                _ => Type::Unknown,
            }
        }
    }