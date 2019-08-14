extern crate embedded_hal as hal;
use hal::blocking::spi;

#[derive(Debug)]
pub enum SpiAction {
    TransferTx,
    TransferRx,
    Write,
}

pub trait Recorder {
    fn log(&mut self, action: SpiAction, data: &[u8]) -> ();
}

pub struct SpiTracker<SPI, R> {
    spi: SPI,
    recorder: R,
}

impl<SPI, R: Recorder> SpiTracker<SPI, R> {
    pub fn new(spi: SPI, recorder: R) -> SpiTracker<SPI, R> {
        SpiTracker {
            spi: spi,
            recorder: recorder,
        }
    }
}

impl<SPI, R, E> spi::Transfer<u8> for SpiTracker<SPI, R>
where
    SPI: spi::Transfer<u8, Error = E>,
    R: Recorder,
{
    /// Error type
    type Error = E;

    /// Wraps self.spi.transfer
    fn transfer<'w>(&mut self, words: &'w mut [u8]) -> Result<&'w [u8], Self::Error> {
        self.recorder.log(SpiAction::TransferTx, words);
        let result = self.spi.transfer(words)?;
        self.recorder.log(SpiAction::TransferRx, result);
        Ok(result)
    }
}

impl<SPI, R, E> spi::Write<u8> for SpiTracker<SPI, R>
where
    SPI: spi::Write<u8, Error = E>,
    R: Recorder,
{
    /// Error type
    type Error = E;

    /// Wraps self.spi.write
    fn write(&mut self, words: &[u8]) -> Result<(), Self::Error> {
        self.recorder.log(SpiAction::Write, words);
        self.spi.write(words)
    }
}
