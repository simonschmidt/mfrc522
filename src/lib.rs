//! A platform agnostic driver to interface the MFRC522 (RFID reader/writer)
//!
//! This driver was built using [`embedded-hal`] traits.
//!
//! [`embedded-hal`]: https://docs.rs/embedded-hal/~0.1
//!
//! # Examples
//!
//! You'll find an example for the Raspeberry Pi in the `examples` directory. You should find an
//! example for ARM Cortex-M microcontrollers on the [`blue-pill`] repository. If that branch is
//! gone, check the master branch.
//!
//! [`blue-pill`]: https://github.com/japaric/blue-pill/tree/singletons/examples
//!
//! # References
//!
//! - [Identification cards - Contactless integrated circuit(s) cards - Proximity cards - Part 3:
//! Initialization and anticollision][1]
//! - [MFRC522 data sheet][2]
//!
//! [1]: http://wg8.de/wg8n1496_17n3613_Ballot_FCD14443-3.pdf
//! [2]: https://www.nxp.com/docs/en/data-sheet/MFRC522.pdf

#![allow(dead_code)]
// TODO deny again
// #![deny(missing_docs)]

// NOTE: OutputPin v1/v2 business will warn
// #![deny(warnings)]
#![no_std]

extern crate embedded_hal as hal;
extern crate generic_array;

use core::mem;

use generic_array::typenum::consts::*;
use generic_array::{ArrayLength, GenericArray};
use hal::blocking::spi;
use hal::digital::OutputPin;
use hal::spi::{Mode, Phase, Polarity};

mod picc;

// #[cfg(test)]
pub mod testutils;

/// Errors
#[derive(Debug)]
pub enum Error<E> {
    /// Wrong Block Character Check (BCC)
    Bcc,
    /// FIFO buffer overflow
    BufferOverflow,
    /// Collision
    Collision,
    /// Wrong CRC
    Crc,
    /// Incomplete RX frame
    IncompleteFrame,
    /// Not enough room in buffer
    BufferTooSmall,
    /// Internal temperature sensor detects overheating
    Overheating,
    /// Parity check failed
    Parity,
    /// Error during MFAuthent operation
    Protocol,
    /// SPI bus error
    Spi(E),
    /// Timeout
    Timeout,
    /// ???
    Wr,
}

// XXX coherence :-(
// impl<SPI> From<SPI::Error> for Error<SPI>
// where
//     SPI: spi::FullDuplex<u8>,
// {
//     fn from(e: SPI::Error) -> Error<SPI> {
//         Error::Spi(e)
//     }
// }

/// MFRC522 driver
pub struct Mfrc522<SPI, NSS> {
    /// TODO make private again
    pub spi: SPI,
    nss: NSS,
}

const ERR_IRQ: u8 = 1 << 1;
const IDLE_IRQ: u8 = 1 << 4;
const RX_IRQ: u8 = 1 << 5;
const TIMER_IRQ: u8 = 1 << 0;

const CRC_IRQ: u8 = 1 << 2;

impl<E, NSS, SPI> Mfrc522<SPI, NSS>
where
    SPI: spi::Transfer<u8, Error = E> + spi::Write<u8, Error = E>,
    NSS: OutputPin,
{
    /// Creates a new driver from a SPI driver and a NSS pin
    pub fn new(spi: SPI, nss: NSS) -> Result<Self, E> {
        let mut mfrc522 = Mfrc522 { spi, nss };

        // soft reset
        mfrc522.command(Command::SoftReset)?;

        while mfrc522.read(Register::Command)? & (1 << 4) != 0 {}

        // configure timer to operate at 10 KHz.
        // f_timer = 13.56 MHz / (2 + TPrescaler + 2)
        mfrc522.write(Register::Demod, 0x4d | (1 << 4))?;
        mfrc522.write(Register::TMode, 0x0 | (1 << 7) | 0b10)?;
        mfrc522.write(Register::TPrescaler, 165)?;

        // configure timer for a 5 ms timeout
        mfrc522.write(Register::ReloadL, 50)?;

        // forces 100% ASK modulation
        // NOTE my tags don't work without this ...
        mfrc522.write(Register::TxAsk, 1 << 6)?;

        // set preset value for the CRC co-processor to 0x6363
        // in accordance to section 6.2.4 of ISO/IEC FCD 14443-3
        mfrc522.write(Register::Mode, (0x3f & (!0b11)) | 0b01)?;

        // enable the antenna
        mfrc522.write(Register::TxControl, 0x80 | 0b11)?;

        Ok(mfrc522)
    }

    /// Stop crypto
    /// Must be called after `self.authenticate` to return to normal functionality
    /// Called by `self.with_authentication`
    pub fn stop_crypto(&mut self) -> Result<(), Error<E>> {
        // Status2Reg[7..0] bits are: TempSensClear I2CForceHS reserved reserved MFCrypto1On ModemState[2:0]
        self.rmw(Register::Status2Reg, |v| v & (!0x08))
            .map_err(Error::Spi)?;
        Ok(())
    }

    /// Run function in authentication context
    /// ensures crypto is stopped after `f` is called
    pub fn with_authentication<F, T>(&mut self, f: F) -> Result<T, Error<E>>
    where
        F: FnOnce(&mut Self) -> Result<T, Error<E>>,
    {
        let result = f(self);
        self.stop_crypto()?;
        result
    }

    /// 10.3.1.9 MFAuthent
    /// Authenticate
    /// `self.stop_crypto` must be called after this to resume
    /// normal operation, prefer `self.with_authentication`
    pub fn authenticate(
        &mut self,
        block_addr: u8,
        sector_key: &Key,
        uid: &Uid,
    ) -> Result<(), Error<E>> {
        let mut tx_buffer: [u8; 12] = [0; 12];
        tx_buffer[0] = picc::AUTH_KEY_A; // TODO arg, also allow key b
        tx_buffer[1] = block_addr;

        let key_bytes = sector_key.bytes();
        for i in 0..(key_bytes.len()) {
            tx_buffer[2 + i] = key_bytes[i];
        }

        // Use the last uid bytes as specified in http://cache.nxp.com/documents/application_note/AN10927.pdf
        // section 3.2.5 "MIFARE Classic Authentication".
        // The only missed case is the MF1Sxxxx shortcut activation,
        // but it requires cascade tag (CT) byte, that is not part of uid.
        let uid_bytes = uid.bytes();
        for i in 0..4 {
            // The last 4 bytes of the UID
            tx_buffer[8 + i] = (uid_bytes[i + uid_bytes.len() - 4]).clone();
        }

        // Start the authentication.
        // TODO in PCD_authinticate only IdleIrq is looked for
        self.communicate(Command::MFAuthent, &tx_buffer, 0x80, 1 << 3)?;

        Ok(())
    }

    /// READ, TODO document
    pub fn mifare_read(&mut self, block_addr: u8, buffer: &mut [u8]) -> Result<(), Error<E>> {
        if buffer.len() < 18 {
            return Err(Error::BufferTooSmall);
        }

        buffer[0] = picc::MIFARE_READ;
        buffer[1] = block_addr;
        let result = self.calculate_crc(&buffer[0..2])?;
        buffer[2] = result[0];
        buffer[3] = result[1];

        // TODO: tx_last_bits or not?
        self.communicate(Command::Transceive, &buffer[0..4], 0, 1 << 3)?;
        self.read_fifo(buffer)?;
        Ok(())
    }

    pub fn mifare_write(
        &mut self,
        block_addr: u8,
        buffer: &[u8],
    ) -> Result<(), Error<E>>{
        if (buffer.len() < 16) {
            return Error::BufferTooSmall;
        }

        self.mifare_transceive(&[picc::MIFARE_WRITE, block_addr])?;
        self.mifare_transceive(buffer)?;
        Ok(())
    }

    fn mifare_transceive(&mut self, tx_buffer: &[u8]) {
        // TODO ensure tx_buffer.len() <= 16

        let mut cmdbuffer = [0; 18];
        cmdbuffer[..tx_buffer.len()].clone_from_slice(tx_buffer);
        let result = self.calculate_crc(&cmdbuffer[..tx_buffer.len()])?;
        cmdbuffer[tx_buffer.len()..tx_buffer.len()+2].copy_from_slice(&result);

        self.communicate(Command::Transceive,  &cmdbuffer[..tx_buffer.len()+2], 0, 1 << 3)?;

        self.read_fifo(&mut cmdbuffer)?;



    }
    /// Sends a REQuest type A to nearby PICCs
    pub fn reqa<'b>(&mut self) -> Result<AtqA, Error<E>> {
        // NOTE REQA is a short frame (7 bits)
        self.transceive(&[picc::REQA], 7)
            .map(|bytes| AtqA { bytes })
    }
    /// Selects an idle PICC
    ///
    /// NOTE currently this only supports single size UIDs
    // TODO anticollision loop
    // TODO add optional UID to select an specific PICC
    pub fn select(&mut self, _atqa: &AtqA) -> Result<Uid, Error<E>> {
        let rx = self.transceive::<U5>(&[picc::SEL_CL1, 0x20], 0)?;

        assert_ne!(
            rx[0],
            picc::CT,
            "double and triple size UIDs are currently not supported"
        );

        let expected_bcc = rx[4];
        let computed_bcc = rx[0] ^ rx[1] ^ rx[2] ^ rx[3];

        // XXX can this ever fail? (buggy PICC?)
        if computed_bcc != expected_bcc {
            return Err(Error::Bcc);
        }

        let mut tx: [u8; 9] = unsafe { mem::uninitialized() };
        tx[0] = picc::SEL_CL1;
        tx[1] = 0x70;
        tx[2..7].copy_from_slice(&rx);

        let crc = self.calculate_crc(&tx[..7])?;
        tx[7..].copy_from_slice(&crc);

        // enable automatic CRC validation during reception
        let rx2 = self.transceive::<U3>(&tx, 0)?;

        let crc2 = self.calculate_crc(&rx2[..1])?;

        if &rx2[1..] != &crc2 {
            return Err(Error::Crc);
        }

        let sak = rx2[0];
        let picc_type = picc::Type::from_sak(sak);


        let compliant = match (sak & (1 << 2) != 0, sak & (1 << 5) != 0) {
            // indicates that the UID is incomplete -- this is unreachable because we only support
            // single size UIDs
            (_, true) => unreachable!(),
            (true, false) => true,
            (false, false) => false,
        };

        Ok(Uid {
            bytes: [rx[0], rx[1], rx[2], rx[3]],
            compliant: compliant,
            picc_type: picc_type,
        })
    }

    /// Returns the version of the MFRC522
    pub fn version(&mut self) -> Result<u8, E> {
        self.read(Register::Version)
    }

    fn calculate_crc(&mut self, data: &[u8]) -> Result<[u8; 2], Error<E>> {
        // stop any ongoing command
        self.command(Command::Idle).map_err(Error::Spi)?;

        // clear the CRC_IRQ interrupt flag
        self.write(Register::DivIrq, 1 << 2).map_err(Error::Spi)?;

        // flush FIFO buffer
        self.flush_fifo_buffer().map_err(Error::Spi)?;

        // write data to transmit to the FIFO buffer
        self.write_many(Register::FifoData, data)
            .map_err(Error::Spi)?;

        self.command(Command::CalcCRC).map_err(Error::Spi)?;

        // TODO timeout when connection to the MFRC522 is lost
        // wait for CRC to complete
        let mut irq;
        loop {
            irq = self.read(Register::DivIrq).map_err(Error::Spi)?;

            if irq & CRC_IRQ != 0 {
                self.command(Command::Idle).map_err(Error::Spi)?;
                let crc = [
                    self.read(Register::CrcResultL).map_err(Error::Spi)?,
                    self.read(Register::CrcResultH).map_err(Error::Spi)?,
                ];

                break Ok(crc);
            }
        }
    }

    fn check_error_register(&mut self) -> Result<(), Error<E>> {
        const PROTOCOL_ERR: u8 = 1 << 0;
        const PARITY_ERR: u8 = 1 << 1;
        const CRC_ERR: u8 = 1 << 2;
        const COLL_ERR: u8 = 1 << 3;
        const BUFFER_OVFL: u8 = 1 << 4;
        const TEMP_ERR: u8 = 1 << 6;
        const WR_ERR: u8 = 1 << 7;

        let err = self.read(Register::Error).map_err(Error::Spi)?;

        if err & PROTOCOL_ERR != 0 {
            Err(Error::Protocol)
        } else if err & PARITY_ERR != 0 {
            Err(Error::Parity)
        } else if err & CRC_ERR != 0 {
            Err(Error::Crc)
        } else if err & COLL_ERR != 0 {
            Err(Error::Collision)
        } else if err & BUFFER_OVFL != 0 {
            Err(Error::BufferOverflow)
        } else if err & TEMP_ERR != 0 {
            Err(Error::Overheating)
        } else if err & WR_ERR != 0 {
            Err(Error::Wr)
        } else {
            Ok(())
        }
    }

    fn command(&mut self, command: Command) -> Result<(), E> {
        self.write(Register::Command, command.value())
    }

    fn flush_fifo_buffer(&mut self) -> Result<(), E> {
        self.write(Register::FifoLevel, 1 << 7)
    }

    fn communicate(
        &mut self,
        cmd: Command,
        tx_buffer: &[u8],
        tx_last_bits: u8,
        rx_align: u8,
    ) -> Result<(), Error<E>> {
        // stop any ongoing command
        self.command(Command::Idle).map_err(Error::Spi)?;

        // clear all interrupt flags
        self.write(Register::ComIrq, 0x7f).map_err(Error::Spi)?;

        // flush FIFO buffer
        self.flush_fifo_buffer().map_err(Error::Spi)?;

        // write data to transmit to the FIFO buffer
        self.write_many(Register::FifoData, tx_buffer)
            .map_err(Error::Spi)?;

        // signal command
        self.command(cmd).map_err(Error::Spi)?;

        // configure short frame and start transmission
        self.write(Register::BitFraming, (rx_align << 4) | tx_last_bits)
            .map_err(Error::Spi)?;

        // TODO timeout when connection to the MFRC522 is lost (?)
        // wait for transmission + reception to complete
        let mut irq;
        loop {
            irq = self.read(Register::ComIrq).map_err(Error::Spi)?;

            if irq & (RX_IRQ | ERR_IRQ | IDLE_IRQ) != 0 {
                break;
            } else if irq & TIMER_IRQ != 0 {
                return Err(Error::Timeout);
            }
        }

        // XXX do we need a guard here?
        // check for any outstanding error
        // if irq & ERR_IRQ != 0 {
        self.check_error_register()?;
        // }

        Ok(())
    }

    fn transceive<RX>(
        &mut self,
        tx_buffer: &[u8],
        tx_last_bits: u8,
    ) -> Result<GenericArray<u8, RX>, Error<E>>
    where
        RX: ArrayLength<u8>,
    {
        self.communicate(Command::Transceive, tx_buffer, tx_last_bits, 1 << 3)?;
        // grab RX data
        let mut rx_buffer: GenericArray<u8, RX> =
            unsafe { mem::MaybeUninit::uninit().assume_init() };
        self.read_fifo(&mut rx_buffer)?;
        Ok(rx_buffer)
    }

    // lowest level  API
    fn read(&mut self, reg: Register) -> Result<u8, E> {
        let mut buffer = [reg.read_address(), 0];

        self.with_nss_low(|mfr| {
            let buffer = mfr.spi.transfer(&mut buffer)?;

            Ok(buffer[1])
        })
    }

    fn read_many<'b>(&mut self, reg: Register, buffer: &'b mut [u8]) -> Result<&'b [u8], E> {
        let byte = reg.read_address();

        self.with_nss_low(move |mfr| {
            mfr.spi.transfer(&mut [byte])?;

            let n = buffer.len();
            for slot in &mut buffer[..n - 1] {
                *slot = mfr.spi.transfer(&mut [byte])?[0];
            }

            buffer[n - 1] = mfr.spi.transfer(&mut [0])?[0];

            Ok(&*buffer)
        })
    }

    fn rmw<F>(&mut self, reg: Register, f: F) -> Result<(), E>
    where
        F: FnOnce(u8) -> u8,
    {
        let byte = self.read(reg)?;
        self.write(reg, f(byte))?;
        Ok(())
    }

    fn write(&mut self, reg: Register, val: u8) -> Result<(), E> {
        self.with_nss_low(|mfr| mfr.spi.write(&[reg.write_address(), val]))
    }

    fn write_many(&mut self, reg: Register, bytes: &[u8]) -> Result<(), E> {
        self.with_nss_low(|mfr| {
            mfr.spi.write(&[reg.write_address()])?;
            mfr.spi.write(bytes)?;

            Ok(())
        })
    }

    fn read_fifo(&mut self, rx_buffer: &mut [u8]) -> Result<(), Error<E>> {
        let received_bytes = self.read(Register::FifoLevel).map_err(Error::Spi)?;

        if received_bytes as usize != rx_buffer.len() {
            return Err(Error::IncompleteFrame);
        }

        self.read_many(Register::FifoData, rx_buffer)
            .map_err(Error::Spi)?;
        Ok(())
    }

    fn with_nss_low<F, T>(&mut self, f: F) -> T
    where
        F: FnOnce(&mut Self) -> T,
    {
        self.nss.set_low();
        let result = f(self);
        self.nss.set_high();

        result
    }
}

/// SPI mode
pub const MODE: Mode = Mode {
    polarity: Polarity::IdleLow,
    phase: Phase::CaptureOnFirstTransition,
};

/// 10.3 MFRC522 command overview (Table 149.)
#[derive(Clone, Copy)]
enum Command {
    Idle,
    Mem,
    GenerateRandomID,
    CalcCRC,
    Transmit,
    NoCmdChange,
    Receive,
    Transceive,
    MFAuthent,
    SoftReset,
}

impl Command {
    fn value(&self) -> u8 {
        match *self {
            Command::Idle => 0b0000,
            Command::Mem => 0b0001,
            Command::GenerateRandomID => 0b0010,
            Command::CalcCRC => 0b0011,
            Command::Transmit => 0b0100,
            Command::NoCmdChange => 0b0111,
            Command::Receive => 0b1000,
            Command::Transceive => 0b1100,
            Command::MFAuthent => 0b1110,
            Command::SoftReset => 0b1111,
        }
    }
}

#[allow(missing_docs)]
#[derive(Clone, Copy)]
pub enum Register {
    BitFraming = 0x0d,
    Coll = 0x0e,
    ComIrq = 0x04,
    Command = 0x01,
    CrcResultH = 0x21,
    CrcResultL = 0x22,
    Demod = 0x19,
    DivIrq = 0x05,
    Error = 0x06,
    FifoData = 0x09,
    FifoLevel = 0x0a,
    ModWidth = 0x24,
    Mode = 0x11,
    ReloadH = 0x2c,
    ReloadL = 0x2d,
    RxMode = 0x13,
    Status2Reg = 0x08,
    TCountValH = 0x2e,
    TCountValL = 0x2f,
    TMode = 0x2a,
    TPrescaler = 0x2b,
    TxAsk = 0x15,
    TxControl = 0x14,
    TxMode = 0x12,
    Version = 0x37,
}

const R: u8 = 1 << 7;
#[allow(dead_code)]
const W: u8 = 0 << 7;

impl Register {
    fn read_address(&self) -> u8 {
        ((*self as u8) << 1) | R
    }

    /// TODO unpub
    pub fn write_address(&self) -> u8 {
        ((*self as u8) << 1) | W
    }
}

/// Answer To reQuest A
pub struct AtqA {
    bytes: GenericArray<u8, U2>,
}

/// Single size UID
#[derive(Debug)]
pub struct Uid {
    bytes: [u8; 4],
    compliant: bool,
    picc_type: picc::Type,
}

impl Uid {
    /// The bytes of the UID
    pub fn bytes(&self) -> &[u8; 4] {
        &self.bytes
    }

    /// Is the PICC compliant with ISO/IEC 14443-4?
    pub fn is_compliant(&self) -> bool {
        self.compliant
    }
}

/// Authentication key
#[derive(Debug)]
pub struct Key {
    bytes: [u8; 6],
}

impl Key {
    /// Create new key
    pub fn new(bytes: [u8; 6]) -> Key {
        Key { bytes: bytes }
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
