use std::{mem::ManuallyDrop, thread, time::Duration};

use anyhow::{Result, anyhow};
use const_format::formatcp;
use embedded_svc::http::client::Client as HttpClient;
use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    hal::prelude::*,
    http::client::{
        Configuration as EspHttpClientConfiguration, EspHttpConnection,
    },
    log::EspLogger,
    nvs::EspDefaultNvsPartition,
    sys,
    wifi::{self, BlockingWifi, EspWifi},
};
use log::{error, info};

const SSID: &str = env!("APP_SSID");
const PASS: &str = env!("APP_PASS");
const API_HOST: &str = env!("APP_API_HOST");

fn main() -> Result<()> {
    sys::link_patches();
    EspLogger::initialize_default();
    info!("HAL init!");

    let peri = Peripherals::take()?;
    let sysl = EspSystemEventLoop::take()?;
    let nvsp = EspDefaultNvsPartition::take()?;

    let mut wifi = ManuallyDrop::new(BlockingWifi::wrap(
        EspWifi::new(peri.modem, sysl.clone(), Some(nvsp))?,
        sysl,
    )?);
    info!("Wi-Fi init!");

    wifi.set_configuration(&wifi::Configuration::Client(
        wifi::ClientConfiguration {
            ssid: SSID.parse().map_err(|()| anyhow!("SSID overflow!"))?,
            auth_method: match PASS {
                "" => wifi::AuthMethod::None,
                _ => wifi::AuthMethod::WPA2WPA3Personal,
            },
            password: PASS
                .parse()
                .map_err(|()| anyhow!("password overflow!"))?,
            ..<_>::default()
        },
    ))?;
    info!("Wi-Fi config set!");

    wifi.start()?;
    info!("Wi-Fi started!");

    info!("Wi-Fi connecting...");
    while let Err(err) = wifi.connect() {
        error!("Wi-Fi connect failed, retrying: {err}");
        thread::sleep(Duration::from_secs(5));
    }
    info!("Wi-Fi connected!");

    info!("waiting for Wi-Fi link up...");
    wifi.wait_netif_up()?;
    info!("Wi-Fi link up!");

    let mut http = HttpClient::wrap(EspHttpConnection::new(
        &EspHttpClientConfiguration {
            crt_bundle_attach: Some(sys::esp_crt_bundle_attach),
            ..<_>::default()
        },
    )?);

    let mut req = http.get(formatcp!("https://{API_HOST}/ping"))?.submit()?;

    let mut buf = vec![0];
    let mut len = 0;

    while let Ok(read) = req.read(&mut buf[len..]) {
        if read == 0 {
            break;
        }

        buf.resize(buf.len() * 2, 0);
        len += read;
    }

    buf.truncate(len);
    info!("got response: {}", String::from_utf8_lossy(&buf));

    Ok(())
}
