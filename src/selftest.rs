    /// Reference results 16.1.1
    pub const V2_0: [u8; 64] = [
        0x00, 0xEB, 0x66, 0xBA, 0x57, 0xBF, 0x23, 0x95, 0xD0, 0xE3, 0x0D, 0x3D, 0x27, 0x89, 0x5C,
        0xDE, 0x9D, 0x3B, 0xA7, 0x00, 0x21, 0x5B, 0x89, 0x82, 0x51, 0x3A, 0xEB, 0x02, 0x0C, 0xA5,
        0x00, 0x49, 0x7C, 0x84, 0x4D, 0xB3, 0xCC, 0xD2, 0x1B, 0x81, 0x5D, 0x48, 0x76, 0xD5, 0x71,
        0x61, 0x21, 0xA9, 0x86, 0x96, 0x83, 0x38, 0xCF, 0x9D, 0x5B, 0x6D, 0xDC, 0x15, 0xBA, 0x3E,
        0x7D, 0x95, 0x3B, 0x2F,
    ];

    /// Compare self test result from FIFO buffer against reference result
    /// None when no reference found
    pub fn check<'a>(version: u8, result: &'a [u8; 64]) -> Option<bool> {
        let reference = V2_0; // TODO based on version
        Some(result.iter().zip(reference.iter()).all(|(a, b)| a == b))
    }

    /// 16.1.1 Self-test
    pub fn self_test(&mut self, rx_buffer: &mut [u8; 64]) -> Result<(), Error<E>> {
        // 10.3.1.4 CalcCRC command last paragraph
        // 9.3.4.7 AutoTestReg register
        // 1. Perform a soft reset
        self.command(Command::SoftReset).map_err(Error::Spi)?;
        while self.read(Register::Command).map_err(Error::Spi)? & (1 << 4) != 0 {}

        // 2. Clear the internal buffer
        self.flush_fifo_buffer().map_err(Error::Spi)?;
        let zeroes: [u8; 24] = [0; 24];
        self.write_many(Register::FifoData, &zeroes)
            .map_err(Error::Spi)?;
        self.command(Command::Mem).map_err(Error::Spi)?;

        // 3. Enable self test
        self.write(Register::AutoTestReg, 0b1001)
            .map_err(Error::Spi)?;

        // 4. Write 00h to the FIFO buffer
        self.write(Register::FifoData, 0).map_err(Error::Spi)?;

        // 5. Start the self test with the CalcCRC command
        self.command(Command::CalcCRC).map_err(Error::Spi)?;

        // 6. The self test is initiated
        // Wait for CalcCRC to complete
        // TODO: What s the "right" way to wait for self-test?
        // The spec doesn't really say, just that there will be 64 bytes in the fifo buffer.
        // However for me that condition is never reached, however if I look at DivIRQ
        //
        // We expect the bufffer
        for _ in 0..255 {
            if self.read(Register::FifoLevel).map_err(Error::Spi)? == 64 {
                hprintln!("FIFO ready!").unwrap();
                break;
            }
        }

        //        let irq = self.read(Register::DivIrq).map_err(Error::Spi)?;
        //        hprintln!("IRQ: {:?}", irq).unwrap();
        //        self.command(Command::Idle).map_err(Error::Spi)?;

        // 7 When the self test has completed...
        // grab RX data
        self.read_fifo(rx_buffer)?;

        // Disable self-test
        self.write(Register::AutoTestReg, 0).map_err(Error::Spi)?;

        // Get version so we know what to expect
        let version = self.version().map_err(Error::Spi)?;
        match selftest::check(version, rx_buffer) {
            Some(true) => Ok(()),
            None => Ok(()),
            Some(false) => Err(Error::SelfTest),
        }
    }