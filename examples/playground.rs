// TODO put links somewhere better
// https://www.nxp.com/docs/en/data-sheet/MFRC522.pdf
// arduino implementation (no copyright) https://github.com/miguelbalboa/rfid/blob/master/src/MFRC522.cpp#L322

#![no_main]
#![no_std]
extern crate cortex_m;

extern crate cortex_m_rt;
extern crate cortex_m_semihosting;
extern crate embedded_hal as hal;
extern crate generic_array;
extern crate mfrc522;
extern crate panic_itm;
extern crate stm32f1xx_hal;

use cortex_m::{iprint, iprintln};
use cortex_m_semihosting::hprintln;

use cortex_m_rt::entry;
use hal::blocking::spi;
use hal::digital::OutputPin;
use mfrc522::testutils::{Recorder, SpiAction, SpiTracker};
use mfrc522::{Key, Mfrc522, Mifare, SectorTrailer};
use stm32f1xx_hal::{pac, prelude::*, spi::Spi};

pub struct ItmRecorder<'a> {
    stim: &'a mut cortex_m::peripheral::itm::Stim,
}

impl<'a> ItmRecorder<'a> {
    pub fn new(stim: &'a mut cortex_m::peripheral::itm::Stim) -> ItmRecorder<'a> {
        ItmRecorder { stim: stim }
    }
}

impl<'a> Recorder for ItmRecorder<'a> {
    fn log(&mut self, action: SpiAction, bytes: &[u8]) {
        match action {
            SpiAction::Write => iprintln!(self.stim, "SpiTransaction::write(vec!{:?}),", bytes),
            SpiAction::TransferTx => iprint!(self.stim, "SpiTransaction::transfer(vec!{:?}", bytes),
            SpiAction::TransferRx => iprintln!(self.stim, ", vec!{:?}),", bytes),
        }
    }
}

macro_rules! setup_mfrc522 {
    ($SPI1:expr, $mapr:expr, $gpioa:ident, $rcc:ident, $clocks:ident, $stim:ident) => {{
        let sck = $gpioa.pa5.into_alternate_push_pull(&mut $gpioa.crl);
        let miso = $gpioa.pa6;
        let mosi = $gpioa.pa7.into_alternate_push_pull(&mut $gpioa.crl);
        let actual_spi = Spi::spi1(
            $SPI1,
            (sck, miso, mosi),
            &mut $mapr,
            mfrc522::MODE,
            1.mhz(),
            $clocks,
            &mut $rcc.apb2,
        );

        // 40 actions, with 40 bytes
        let recorder = ItmRecorder::new($stim);
        let spi = SpiTracker::new(actual_spi, recorder);

        let nss = $gpioa.pa4.into_push_pull_output(&mut $gpioa.crl);

        // Note: Can infinite loop if device never enters ready state
        // after soft reset

        let mfrc522 = Mfrc522::new(spi, nss).unwrap();
        mfrc522
    }};
}

fn test_something<E, SPI, NSS: OutputPin>(
    mfrc522: &mut Mfrc522<SPI, NSS>,
) -> Result<(), mfrc522::Error<E>>
where
    SPI: spi::Transfer<u8, Error = E> + spi::Write<u8, Error = E>,
{
    let atqa = mfrc522.reqa()?;

    let uid = mfrc522.select(&atqa)?;

    let mut buffer: [u8; 18] = [1; 18];

    let value_block_addr = 6;   // Data block 2
    let trailer_addr = 7;

    mfrc522.with_authentication(|mfrc522| {

        let key = Key::default();

        // Auth trailer and write our hing
        mfrc522.authenticate(trailer_addr, &key, &uid)?;

        // Read the current value, we don't wan to modify keys
        mfrc522.mifare_read(trailer_addr, &mut buffer[..])?;

        // Update the access bits (value block on 2, otherwise default)
        buffer[6] = 0xaa;
        buffer[7] = 0x57;
        buffer[8] = 0x85;

        mfrc522.mifare_write(
            trailer_addr,
            &buffer,
        )?;

        // Read the value_block
        mfrc522.mifare_read(value_block_addr, &mut buffer[..16])?;
        hprintln!("Before: {:?}", &buffer[..16]).unwrap();

        // Set as value block
        mfrc522.write_value_block(value_block_addr, 15, &mut buffer)?;
        mfrc522.mifare_read(value_block_addr, &mut buffer[..16])?;
        hprintln!("Post value: {:?}", &buffer[..16]).unwrap();
        Ok(())
    })?;

    Ok(())
}

#[entry]
fn main() -> ! {
    let mut cp = cortex_m::Peripherals::take().unwrap();
    let dp = pac::Peripherals::take().unwrap();

    let stim = &mut cp.ITM.stim[0];
    let mut rcc = dp.RCC.constrain();
    let mut afio = dp.AFIO.constrain(&mut rcc.apb2);
    let mut flash = dp.FLASH.constrain();
    let mut gpioa = dp.GPIOA.split(&mut rcc.apb2);

    let clocks = rcc.cfgr.freeze(&mut flash.acr);
    iprintln!(stim, "Sysclk: {:?}", clocks.sysclk().0);

    let result = {
        let mut mfrc522 = setup_mfrc522!(dp.SPI1, afio.mapr, gpioa, rcc, clocks, stim);

        let result = test_something(&mut mfrc522);
        result
    };
    iprintln!(stim, "Result: {:?}", result);

    loop {}
}
