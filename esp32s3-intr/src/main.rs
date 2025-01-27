#![no_std]
#![no_main]

use core::time::Duration;

use esp_hal::{
    delay::Delay,
    gpio::{Level, Output},
    main,
    rtc_cntl::{sleep::TimerWakeupSource, Rtc},
};
use panic_halt as _;

#[main]
fn main() -> ! {
    let p = esp_hal::init(<_>::default());

    let mut rtc = Rtc::new(p.LPWR);
    let mut led = Output::new(p.GPIO3, Level::Low);
    let delay = Delay::new();

    led.set_high();
    delay.delay_millis(500);
    led.set_low();

    rtc.sleep_deep(&[&TimerWakeupSource::new(Duration::from_secs(5))]);
}
