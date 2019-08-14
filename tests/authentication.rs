extern crate embedded_hal;
extern crate embedded_hal_mock;
extern crate mfrc522;

use embedded_hal::digital::v1::OutputPin;

use embedded_hal_mock::spi::{Mock as SpiMock, Transaction as SpiTransaction};
use embedded_hal_mock::MockError;
use mfrc522::{Error, Key, Mfrc522, Mifare};

struct MockPin {}

impl OutputPin for MockPin {
    fn set_low(&mut self) {}
    fn set_high(&mut self) {}
}

#[test]
fn test_read_sector() -> () {
    inner_read_sector().unwrap();
}

fn inner_read_sector() -> Result<(), Error<MockError>> {
    // Configure expectations
    let expectations = [
        SpiTransaction::write(vec![2, 15]),
        SpiTransaction::transfer(vec![130, 0], vec![15, 32]),
        SpiTransaction::write(vec![50, 93]),
        SpiTransaction::write(vec![84, 130]),
        SpiTransaction::write(vec![86, 165]),
        SpiTransaction::write(vec![90, 50]),
        SpiTransaction::write(vec![42, 64]),
        SpiTransaction::write(vec![34, 61]),
        SpiTransaction::write(vec![40, 131]),
        SpiTransaction::write(vec![2, 0]),
        SpiTransaction::write(vec![8, 127]),
        SpiTransaction::write(vec![20, 128]),
        SpiTransaction::write(vec![18]),
        SpiTransaction::write(vec![38]),
        SpiTransaction::write(vec![2, 12]),
        SpiTransaction::write(vec![26, 135]),
        SpiTransaction::transfer(vec![136, 0], vec![135, 101]),
        SpiTransaction::transfer(vec![140, 0], vec![0, 0]),
        SpiTransaction::transfer(vec![148, 0], vec![0, 2]),
        SpiTransaction::transfer(vec![146], vec![0]),
        SpiTransaction::transfer(vec![146], vec![4]),
        SpiTransaction::transfer(vec![0], vec![0]),
        SpiTransaction::write(vec![2, 0]),
        SpiTransaction::write(vec![8, 127]),
        SpiTransaction::write(vec![20, 128]),
        SpiTransaction::write(vec![18]),
        SpiTransaction::write(vec![147, 32]),
        SpiTransaction::write(vec![2, 12]),
        SpiTransaction::write(vec![26, 128]),
        SpiTransaction::transfer(vec![136, 0], vec![128, 100]),
        SpiTransaction::transfer(vec![140, 0], vec![0, 0]),
        SpiTransaction::transfer(vec![148, 0], vec![0, 5]),
        SpiTransaction::transfer(vec![146], vec![0]),
        SpiTransaction::transfer(vec![146], vec![198]),
        SpiTransaction::transfer(vec![146], vec![180]),
        SpiTransaction::transfer(vec![146], vec![236]),
        SpiTransaction::transfer(vec![146], vec![249]),
        SpiTransaction::transfer(vec![0], vec![103]),
        SpiTransaction::write(vec![2, 0]),
        SpiTransaction::write(vec![10, 4]),
        SpiTransaction::write(vec![20, 128]),
        SpiTransaction::write(vec![18]),
        SpiTransaction::write(vec![147, 112, 198, 180, 236, 249, 103]),
        SpiTransaction::write(vec![2, 3]),
        SpiTransaction::transfer(vec![138, 0], vec![3, 4]),
        SpiTransaction::write(vec![2, 0]),
        SpiTransaction::transfer(vec![196, 0], vec![0, 168]),
        SpiTransaction::transfer(vec![194, 0], vec![0, 170]),
        SpiTransaction::write(vec![2, 0]),
        SpiTransaction::write(vec![8, 127]),
        SpiTransaction::write(vec![20, 128]),
        SpiTransaction::write(vec![18]),
        SpiTransaction::write(vec![147, 112, 198, 180, 236, 249, 103, 168, 170]),
        SpiTransaction::write(vec![2, 12]),
        SpiTransaction::write(vec![26, 128]),
        SpiTransaction::transfer(vec![136, 0], vec![128, 100]),
        SpiTransaction::transfer(vec![140, 0], vec![0, 0]),
        SpiTransaction::transfer(vec![148, 0], vec![0, 3]),
        SpiTransaction::transfer(vec![146], vec![0]),
        SpiTransaction::transfer(vec![146], vec![8]),
        SpiTransaction::transfer(vec![146], vec![182]),
        SpiTransaction::transfer(vec![0], vec![221]),
        SpiTransaction::write(vec![2, 0]),
        SpiTransaction::write(vec![10, 4]),
        SpiTransaction::write(vec![20, 128]),
        SpiTransaction::write(vec![18]),
        SpiTransaction::write(vec![8]),
        SpiTransaction::write(vec![2, 3]),
        SpiTransaction::transfer(vec![138, 0], vec![3, 4]),
        SpiTransaction::write(vec![2, 0]),
        SpiTransaction::transfer(vec![196, 0], vec![0, 182]),
        SpiTransaction::transfer(vec![194, 0], vec![0, 221]),
        SpiTransaction::write(vec![2, 0]),
        SpiTransaction::write(vec![8, 127]),
        SpiTransaction::write(vec![20, 128]),
        SpiTransaction::write(vec![18]),
        SpiTransaction::write(vec![
            96, 0, 255, 255, 255, 255, 255, 255, 198, 180, 236, 249,
        ]),
        SpiTransaction::write(vec![2, 14]),
        SpiTransaction::write(vec![26, 128]),
        SpiTransaction::transfer(vec![136, 0], vec![128, 20]),
        SpiTransaction::transfer(vec![140, 0], vec![0, 0]),
        SpiTransaction::write(vec![2, 0]),
        SpiTransaction::write(vec![10, 4]),
        SpiTransaction::write(vec![20, 128]),
        SpiTransaction::write(vec![18]),
        SpiTransaction::write(vec![48, 0]),
        SpiTransaction::write(vec![2, 3]),
        SpiTransaction::transfer(vec![138, 0], vec![3, 4]),
        SpiTransaction::write(vec![2, 0]),
        SpiTransaction::transfer(vec![196, 0], vec![0, 2]),
        SpiTransaction::transfer(vec![194, 0], vec![0, 168]),
        SpiTransaction::write(vec![2, 0]),
        SpiTransaction::write(vec![8, 127]),
        SpiTransaction::write(vec![20, 128]),
        SpiTransaction::write(vec![18]),
        SpiTransaction::write(vec![48, 0, 2, 168]),
        SpiTransaction::write(vec![2, 12]),
        SpiTransaction::write(vec![26, 128]),
        SpiTransaction::transfer(vec![136, 0], vec![128, 68]),
        SpiTransaction::transfer(vec![136, 0], vec![0, 100]),
        SpiTransaction::transfer(vec![140, 0], vec![0, 0]),
        SpiTransaction::transfer(vec![148, 0], vec![0, 18]),
        SpiTransaction::transfer(vec![146], vec![0]),
        SpiTransaction::transfer(vec![146], vec![198]),
        SpiTransaction::transfer(vec![146], vec![180]),
        SpiTransaction::transfer(vec![146], vec![236]),
        SpiTransaction::transfer(vec![146], vec![249]),
        SpiTransaction::transfer(vec![146], vec![103]),
        SpiTransaction::transfer(vec![146], vec![8]),
        SpiTransaction::transfer(vec![146], vec![4]),
        SpiTransaction::transfer(vec![146], vec![0]),
        SpiTransaction::transfer(vec![146], vec![98]),
        SpiTransaction::transfer(vec![146], vec![99]),
        SpiTransaction::transfer(vec![146], vec![100]),
        SpiTransaction::transfer(vec![146], vec![101]),
        SpiTransaction::transfer(vec![146], vec![102]),
        SpiTransaction::transfer(vec![146], vec![103]),
        SpiTransaction::transfer(vec![146], vec![104]),
        SpiTransaction::transfer(vec![146], vec![105]),
        SpiTransaction::transfer(vec![146], vec![117]),
        SpiTransaction::transfer(vec![0], vec![25]),
        SpiTransaction::transfer(vec![144, 0], vec![0, 9]),
        SpiTransaction::write(vec![16, 1]),
    ];

    let spi = SpiMock::new(&expectations[..]);
    let nss = MockPin {};
    let mut mfrc522 = Mfrc522::new(spi, nss).map_err(Error::Spi)?;

    let key = Key::default();

    let uid = mfrc522.reqa().and_then(|atqa| mfrc522.select(&atqa))?;
    mfrc522.with_authentication(|mfrc522| {
        let block_addr = 0;
        let mut buffer: [u8; 18] = [0; 18];

        mfrc522.authenticate(block_addr, &key, &uid)?;
        mfrc522.mifare_read(block_addr, &mut buffer[..])?;
        Ok(())
    })
}
