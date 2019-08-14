use core::fmt;

use super::Error;

/// Authentication key
#[derive(Debug)]
pub struct Key {
    bytes: [u8; 6],
}

impl Key {
    /// Create new key
    pub fn new(bytes: [u8; 6]) -> Key {
        Key { bytes }
    }

    /// Get the default key
    pub fn default() -> Key {
        Key::new([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    }

    /// The bytes of the key
    pub fn bytes(&self) -> &[u8; 6] {
        &self.bytes
    }
}

pub struct AccessBits {
    /// Contains bytes b6b7b8b9
    bits: u32,
}

pub struct SectorTrailer<'a> {
    bytes: &'a [u8],
}

impl<'a> SectorTrailer<'a> {
    pub fn access_bits(&self) -> AccessBits {
        let bits: u32 = ((self.bytes[6] as u32) << 24)
            | ((self.bytes[7] as u32) << 16)
            | ((self.bytes[8] as u32) << 8)
            | (self.bytes[9] as u32);
        AccessBits::new(bits)
    }

    pub fn key_a(&self) -> Key {
        let mut bytes: [u8; 6] = [0; 6];
        bytes[..].copy_from_slice(&self.bytes[..6]);
        Key { bytes }
    }

    pub fn key_b(&self) -> Key {
        let mut bytes: [u8; 6] = [0; 6];
        bytes[..].copy_from_slice(&self.bytes[10..15]);
        Key { bytes }
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    pub fn new<E>(bytes: &'a [u8]) -> Result<SectorTrailer<'a>, Error<E>> {
        if bytes.len() != 16 {
            return Err(Error::BufferSize);
        }
        Ok(SectorTrailer { bytes })
    }
}

#[derive(Debug, PartialEq)]
pub enum Keys {
    A,
    B,
    AorB,
    None,
}

#[derive(PartialEq)]
pub struct SectorAccess {
    c: u8,
}

#[derive(Debug, PartialEq)]
pub struct DataAccess {
    c: u8,
}

impl SectorAccess {
    // Mifare datasheet 8.7.2

    pub fn from_bits(c: u8) -> Result<SectorAccess, ()> {
        if c > 0b111 {
            // TODO proper error
            return Err(());
        }
        Ok(SectorAccess { c })
    }

    /// Access condition for reading access bits
    pub fn access_bits_r(&self) -> Keys {
        match self.c {
            0b000 => Keys::A,
            0b010 => Keys::A,
            0b100 => Keys::AorB,
            0b110 => Keys::AorB,
            0b001 => Keys::A,
            0b011 => Keys::AorB,
            0b101 => Keys::AorB,
            0b111 => Keys::AorB,
            _ => unreachable!(),
        }
    }

    /// Access condition for writing access bits
    pub fn access_bits_w(&self) -> Keys {
        match self.c {
            0b000 => Keys::None,
            0b010 => Keys::None,
            0b100 => Keys::None,
            0b110 => Keys::None,
            0b001 => Keys::A,
            0b011 => Keys::B,
            0b101 => Keys::B,
            0b111 => Keys::None,
            _ => unreachable!(),
        }
    }

    /// Access condition for reading key A
    pub fn key_a_r(&self) -> Keys {
        Keys::None
    }

    /// Access condition for writing key A
    pub fn key_a_w(&self) -> Keys {
        match self.c {
            0b000 => Keys::A,
            0b010 => Keys::None,
            0b100 => Keys::B,
            0b110 => Keys::None,
            0b001 => Keys::A,
            0b011 => Keys::B,
            0b101 => Keys::None,
            0b111 => Keys::None,
            _ => unreachable!(),
        }
    }

    /// Access condition for reading key B
    pub fn key_b_r(&self) -> Keys {
        match self.c {
            0b000 => Keys::A,
            0b010 => Keys::A,
            0b100 => Keys::None,
            0b110 => Keys::None,
            0b001 => Keys::A,
            0b011 => Keys::None,
            0b101 => Keys::None,
            0b111 => Keys::None,
            _ => unreachable!(),
        }
    }

    /// Access condition for writing key B
    pub fn key_b_w(&self) -> Keys {
        match self.c {
            0b000 => Keys::A,
            0b010 => Keys::None,
            0b100 => Keys::B,
            0b110 => Keys::None,
            0b001 => Keys::A,
            0b011 => Keys::B,
            0b101 => Keys::None,
            0b111 => Keys::None,
            _ => unreachable!(),
        }
    }
}

impl DataAccess {
    pub fn from_bits(c: u8) -> Result<DataAccess, u8> {
        if c > 0b111 {
            // TODO proper error
            return Err(c);
        }
        Ok(DataAccess { c })
    }

    /// Access condition for read
    pub fn r(&self) -> Keys {
        match self.c {
            0b000 => Keys::AorB,
            0b010 => Keys::AorB,
            0b100 => Keys::AorB,
            0b110 => Keys::AorB,
            0b001 => Keys::AorB,
            0b011 => Keys::B,
            0b101 => Keys::B,
            0b111 => Keys::None,
            _ => unreachable!(),
        }
    }

    /// Access condition for write
    pub fn w(&self) -> Keys {
        match self.c {
            0b000 => Keys::AorB,
            0b010 => Keys::None,
            0b100 => Keys::B,
            0b110 => Keys::B,
            0b001 => Keys::None,
            0b011 => Keys::B,
            0b101 => Keys::None,
            0b111 => Keys::None,
            _ => unreachable!(),
        }
    }

    /// Access condition for increment
    pub fn inc(&self) -> Keys {
        match self.c {
            0b000 => Keys::AorB,
            0b010 => Keys::None,
            0b100 => Keys::None,
            0b110 => Keys::B,
            0b001 => Keys::None,
            0b011 => Keys::None,
            0b101 => Keys::None,
            0b111 => Keys::None,
            _ => unreachable!(),
        }
    }

    /// Access condition for decrement, transfer, restore
    pub fn dec(&self) -> Keys {
        match self.c {
            0b000 => Keys::AorB,
            0b010 => Keys::None,
            0b100 => Keys::None,
            0b110 => Keys::AorB,
            0b001 => Keys::AorB,
            0b011 => Keys::None,
            0b101 => Keys::None,
            0b111 => Keys::None,
            _ => unreachable!(),
        }
    }
}

impl AccessBits {
    pub fn new(bits: u32) -> AccessBits {
        return AccessBits { bits };
    }
    pub fn sector_access(&self) -> Result<SectorAccess, ()> {
        let c = self.get_access_bits(3);
        // Known to be in range, could unwrap
        SectorAccess::from_bits(c)
    }

    /// Access for the data block, 0, 1 or 2
    pub fn data_access(&self, block_ix: u32) -> Result<DataAccess, u8> {
        if block_ix > 2 {
            // TODO proper error
            return Err(0);
        }
        let c = self.get_access_bits(block_ix);
        DataAccess::from_bits(c)
    }

    fn get_access_bits(&self, block_ix: u32) -> u8 {
        // b6 contains redundancy
        let b7 = (self.bits >> 16) & 0xff;
        let b8 = (self.bits >> 8) & 0xff;
        // b9 is user data

        let c1 = (b7 >> (4 + block_ix)) & 1;
        let c2 = (b8 >> block_ix) & 1;
        let c3 = (b8 >> (4 + block_ix)) & 1;

        let c: u8 = ((c1 << 2) | (c2 << 1) | c3) as u8;
        c
    }
}

impl fmt::Debug for AccessBits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.sector_access().unwrap();
        let d_0 = self.data_access(0).unwrap();
        let d_1 = self.data_access(1).unwrap();
        let d_2 = self.data_access(2).unwrap();

        write!(
            f,
             "AccessBits {{ bits = 0x{:x}, sector_access: {:?}, data0 = {:?}, data1={:?}, data2={:?} }}",
             self.bits, s, d_0, d_1, d_2
        )
    }
}

impl fmt::Debug for SectorAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SectorAccess {{ c: 0x{:03b} }}", self.c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Given access bits, compares computed vs provided sector and data access
    // looks at block 0 for data.
    macro_rules! access_bits_test {
        ($($name:ident: (
        $bits:expr,
        (
            $access_bits_r:expr,
            $access_bits_w:expr,
            $key_a_w:expr,
            $key_b_r:expr,
            $key_b_w:expr,
        ),
        (
            $r:expr,
            $w:expr,
            $inc:expr,
            $dec:expr,
        )
        ),)*) => {
        $(
          #[test]
          fn $name() {
            let bits: u32 = $bits;
            let access = AccessBits::new(bits);
            let sector_access = access.sector_access().unwrap();
            let data_access = access.data_access(0).unwrap();

            assert_eq!(sector_access.access_bits_r(), $access_bits_r);
            assert_eq!(sector_access.access_bits_w(), $access_bits_w);
            assert_eq!(sector_access.key_a_w(), $key_a_w);
            assert_eq!(sector_access.key_b_r(), $key_b_r);
            assert_eq!(sector_access.key_b_w(), $key_b_w);

            assert_eq!(data_access.r(), $r);
            assert_eq!(data_access.w(), $w);
            assert_eq!(data_access.inc(), $inc);
            assert_eq!(data_access.dec(), $dec);
          }
        )*
        }
    }

    access_bits_test! {
        access_bits_default: (
            0xff078000,
            (Keys::A, Keys::A, Keys::A, Keys::A, Keys::A,),
            (Keys::AorB, Keys::AorB, Keys::AorB, Keys::AorB,)
        ),
        access_bits_read_only: (
            0x078f0f00,
            (Keys::AorB, Keys::None, Keys::None, Keys::None, Keys::None,),
            (Keys::AorB, Keys::None, Keys::None, Keys::None,)
        ),
    }
}
