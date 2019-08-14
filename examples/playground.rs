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
use mfrc522::testutils::{Recorder, SpiTracker, SpiAction};
use mfrc522::{Key, Mfrc522};
use stm32f1xx_hal::{pac, prelude::*, spi::Spi};


pub struct ItmRecorder<'a> {
    stim: &'a mut cortex_m::peripheral::itm::Stim,
}


impl<'a> ItmRecorder<'a> {
    pub fn new(stim: &'a mut cortex_m::peripheral::itm::Stim) -> ItmRecorder<'a> {
        ItmRecorder {
            stim: stim,
        }
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
    // stim: &mut cortex_m::peripheral::itm::Stim,
) -> Result<(), mfrc522::Error<E>>
where
    SPI: spi::Transfer<u8, Error = E> + spi::Write<u8, Error = E>,
{
    //    let key = Key::default();
    //
    //    let uid = mfrc522.reqa().and_then(|atqa| mfrc522.select(&atqa))?;
    //
    //    mfrc522.with_authentication(|mfrc522| {
    //        let block_addr = 0;
    //        mfrc522.authenticate(block_addr, &key, &uid)?;
    //        Ok(())
    //    })?;

    //mfrc522.print("// reqa");
    let atqa = mfrc522.reqa()?;

    //mfrc522.print("// select");
    let uid = mfrc522.select(&atqa)?;

    //mfrc522.print("// with_auth");
    mfrc522.with_authentication(|mfrc522| {
        let block_addr = 0;

        let key = Key::default();

        //mfrc522.print("// authenticate (block 0, default key)");
        mfrc522.authenticate(block_addr, &key, &uid)?;

        //mfrc522.print("// mifare_read (sector 0)");
        let mut buffer: [u8; 18] = [0; 18];
        mfrc522.mifare_read(block_addr, &mut buffer[..])?;
        hprintln!("Buffer: {:?}", &buffer[..]).unwrap();
        Ok(())
    })?;

    //mfrc522.print("// </with_auth>");
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
    // let mut gpioc = dp.GPIOC.split(&mut rcc.apb2);

    let clocks = rcc.cfgr.freeze(&mut flash.acr);
    iprintln!(stim, "Sysclk: {:?}", clocks.sysclk().0);

    let result = {
        let mut mfrc522 = setup_mfrc522!(dp.SPI1, afio.mapr, gpioa, rcc, clocks, stim);

        let result = test_something(&mut mfrc522);
        result
    };
    iprintln!(stim, "Result: {:?}", result);

    loop {
        //        mfrc522.flush();
        //        iprintln!(_stim, "-------");
        //        let result = test_something(&mut mfrc522);
        //        mfrc522.flush();
        //        iprintln!(_stim, "* {:?}", result);
    }
}
