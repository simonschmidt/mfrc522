use hal::blocking::spi;
use hal::digital::OutputPin;

use super::{Command, Error, Mfrc522, Register};
use crate::access;
use crate::picc;

pub trait Mifare {
    type Error;
    /// Reads 16 bytes (+ 2 bytes CRC_A) from the active PICC.
    /// The block must be authenticated.
    /// Based on: https://github.com/miguelbalboa/rfid/blob/1.4.4/src/MFRC522.cpp#L915
    fn mifare_read(&mut self, block_addr: u8, buffer: &mut [u8]) -> Result<(), Error<Self::Error>>;

    /// Writes 16 bytes to the active PICC.
    /// Based on: https://github.com/miguelbalboa/rfid/blob/1.4.4/src/MFRC522.cpp#L955
    fn mifare_write(
        &mut self,
        block_addr: u8, // MIFARE Classic: The block (0-0xff) number.
        buffer: &[u8],  // The 16 bytes to write to the PICC
    ) -> Result<(), Error<Self::Error>>;

    /// Wrapper for MIFARE protocol communication.
    /// Based on: https://github.com/miguelbalboa/rfid/blob/1.4.4/src/MFRC522.cpp#L1227
    fn mifare_transceive(
        &mut self,
        send_data: &[u8],
        cmd_buffer: &mut [u8],
    ) -> Result<(), Error<Self::Error>>;

    fn mifare_two_step(
        &mut self,
        cmd: u8,
        block_addr: u8,
        data: &[u8],
    ) -> Result<(), Error<Self::Error>>;

    fn write_value_block(
        &mut self,
        block_addr: u8,
        value: i32,
        buffer: &mut [u8],
    ) -> Result<(), Error<Self::Error>>;
}

impl<E, NSS, SPI> Mifare for Mfrc522<SPI, NSS>
where
    SPI: spi::Transfer<u8, Error = E> + spi::Write<u8, Error = E>,
    NSS: OutputPin,
{
    type Error = E;

    fn mifare_read(&mut self, block_addr: u8, buffer: &mut [u8]) -> Result<(), Error<E>> {
        if buffer.len() < 18 {
            return Err(Error::BufferSize);
        }

        buffer[0] = picc::MIFARE_READ;
        buffer[1] = block_addr;
        let result = self.calculate_crc(&buffer[0..2])?;
        buffer[2] = result[0];
        buffer[3] = result[1];

        // TODO: tx_last_bits or not?
        self.communicate(Command::Transceive, &buffer[0..4], 0, 1 << 3)?;
        self.read_fifo(buffer)?;
        // TODO CRC
        Ok(())
    }

    fn mifare_write(
        &mut self,
        block_addr: u8, // MIFARE Classic: The block (0-0xff) number.
        buffer: &[u8],  // The 16 bytes to write to the PICC
    ) -> Result<(), Error<E>> {
        if buffer.len() < 16 {
            return Err(Error::BufferSize);
        }

        let mut transceive_buffer = [0; 18];

        // Mifare Classic protocol requires two communications to perform a write.
        // Step 1: Tell the PICC we want to write to block blockAddr.
        let write_cmd: [u8; 2] = [picc::MIFARE_WRITE, block_addr];

        self.mifare_transceive(&write_cmd, &mut transceive_buffer)?; // Adds CRC_A and checks that the response is MF_ACK.

        // Step 2: Transfer the data
        self.mifare_transceive(buffer, &mut transceive_buffer)?; // Adds CRC_A and checks that the response is MF_ACK.
        Ok(())
    }

    /// Write value into a value block
    /// Based on: https://github.com/miguelbalboa/rfid/blob/1.4.4/src/MFRC522.cpp#L1145
    fn write_value_block(
        &mut self,
        block_addr: u8,
        value: i32,
        buffer: &mut [u8],
    ) -> Result<(), Error<E>> {
        if (buffer.len() != 18) {
            return Err(Error::BufferSize);
        }
        // Translate the int32_t into 4 bytes; repeated 2x in value block
        buffer[0] = (value & 0xFF) as u8;
        buffer[1] = ((value >> 8) & 0xFF) as u8;
        buffer[2] = ((value >> 16) & 0xFF) as u8;
        buffer[3] = ((value >> 24) & 0xFF) as u8;
        buffer[8] = buffer[0];
        buffer[9] = buffer[1];
        buffer[10] = buffer[2];
        buffer[11] = buffer[3];

        // Inverse 4 bytes also found in value block
        buffer[4] = !buffer[0];
        buffer[5] = !buffer[1];
        buffer[6] = !buffer[2];
        buffer[7] = !buffer[3];

        // Address 2x with inverse address 2x
        buffer[12] = block_addr;
        buffer[13] = !block_addr;
        buffer[14] = buffer[12];
        buffer[15] = buffer[13];

        self.mifare_write(block_addr, buffer)
    }

    fn mifare_two_step(&mut self, cmd: u8, block_addr: u8, data: &[u8]) -> Result<(), Error<E>> {
        if (data.len() != 4) {
            return Err(Error::BufferSize);
        }
        let mut transceive_buffer = [0; 18];

        let mut cmd_buffer = [cmd, block_addr];
        self.mifare_transceive(&cmd_buffer, &mut transceive_buffer)?;
        self.mifare_transceive(&data, &mut transceive_buffer);

        Ok(())
    }

    fn mifare_transceive(
        &mut self,
        send_data: &[u8],
        cmd_buffer: &mut [u8],
    ) -> Result<(), Error<E>> {
        if send_data.len() > 16 {
            return Err(Error::BufferSize);
        }

        if cmd_buffer.len() < send_data.len() + 2 {
            return Err(Error::BufferSize);
        }

        cmd_buffer[..send_data.len()].copy_from_slice(send_data);
        let crc = self.calculate_crc(&cmd_buffer[..send_data.len()])?;
        cmd_buffer[send_data.len()] = crc[0];
        cmd_buffer[send_data.len() + 1] = crc[1];

        self.communicate(
            Command::Transceive,
            &cmd_buffer[..(send_data.len() + 2)],
            0,
            1 << 3,
        )?;

        // Expect exactly one byte returned
        self.read_fifo(&mut cmd_buffer[..1])?;

        let control = self.read(Register::Control).map_err(Error::Spi)?;
        let last_bits = control & 0x07;
        if last_bits != 4 {
            // TODO: Another error type?
            return Err(Error::Protocol);
        }

        if cmd_buffer[0] != picc::MF_ACK {
            return Err(Error::MifareNack);
        }
        Ok(())
    }
}
