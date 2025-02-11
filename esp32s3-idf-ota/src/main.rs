// for esp-idf-svc OTA
#![expect(unexpected_cfgs)]

use std::{mem, thread, time::Duration};

use anyhow::{bail, Result};
use embedded_svc::io::Write;
use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    hal::prelude::*,
    http::server::{self, EspHttpServer},
    log::EspLogger,
    nvs::EspDefaultNvsPartition,
    ota::EspOta,
    sys,
    wifi::{self, BlockingWifi, EspWifi},
};
use log::{error, info};

const SSID: &str = env!("WIFI_SSID");
const PASS: &str = env!("WIFI_PASS");

// pull package metadata from Cargo.toml to build OTA images.
sys::esp_app_desc!();

fn main() -> Result<()> {
    sys::link_patches();
    EspLogger::initialize_default();
    info!("ESP-IDF init!");

    let mut ota = EspOta::new()?;
    ota.mark_running_slot_valid()?;
    drop(ota);

    let p = Peripherals::take()?;
    let el = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;

    wifi_connect({
        BlockingWifi::wrap(EspWifi::new(p.modem, el.clone(), Some(nvs))?, el)?
    })?;

    thread::spawn(ota_server);

    Ok(())
}

fn wifi_connect(mut wifi: BlockingWifi<EspWifi<'static>>) -> Result<()> {
    wifi.set_configuration(&wifi::Configuration::Client(
        wifi::ClientConfiguration {
            ssid: SSID
                .parse()
                .inspect_err(|()| {
                    error!(
                        "Wi-Fi SSID too long, using first 32 chars: `{}`",
                        PASS
                    );
                })
                .unwrap_or_else(|()| SSID[..32].parse().unwrap()),
            password: PASS
                .parse()
                .inspect_err(|()| {
                    error!(
                        "Wi-Fi password too long, using first 32 chars: `{}`",
                        PASS
                    );
                })
                .unwrap_or_else(|()| PASS[..64].parse().unwrap()),
            auth_method: match PASS {
                "" => wifi::AuthMethod::None,
                _ => wifi::AuthMethod::WPA2WPA3Personal,
            },
            ..<_>::default()
        },
    ))?;
    info!("Wi-Fi config set!");

    wifi.start()?;
    info!("Wi-Fi driver started!");

    info!("connecting to AP...");
    for i in 0..5 {
        if let Err(err) = wifi.connect() {
            if i == 4 {
                bail!(err);
            } else {
                error!(
                    "failed to connect to AP, retrying {} more times...",
                    4 - i
                );
            }
        }
    }
    info!("AP connected!");

    info!("waiting for netif bringup...");
    wifi.wait_netif_up()?;
    info!("netif is up!");

    info!("Wi-Fi connected!");
    let dhcp = wifi.wifi().sta_netif().get_ip_info()?;
    info!("DHCP info:");
    info!("  IP: {}", dhcp.ip);
    info!("  Subnet: {}", dhcp.subnet);
    info!("  DNS: {:?}, {:?}", dhcp.dns, dhcp.secondary_dns);

    mem::forget(wifi);
    Ok(())
}

fn ota_server() -> Result<()> {
    let mut server = EspHttpServer::new(&server::Configuration {
        session_timeout: Duration::from_secs(10),
        ..<_>::default()
    })?;

    server.fn_handler("/", server::Method::Get, |req| -> Result<()> {
        info!("got root request!");
        let mut res = req.into_ok_response()?;
        res.write_all(b"hello!")?;
        res.flush()?;
        Ok(())
    })?;

    server.fn_handler(
        "/ota",
        server::Method::Post,
        |mut req| -> Result<()> {
            info!("got update request!");

            match EspOta::new() {
                Err(_) => {
                    let mut res = req.into_status_response(423)?;
                    res.write_all(b"another OTA update already occurring!")?;
                    res.flush()?;
                    bail!("user attempted concurrent firmware update!");
                }
                Ok(mut ota) => {
                    let mut update = ota.initiate_update()?;

                    let mut buf = vec![0; 4096];
                    loop {
                        match req.read(&mut buf) {
                            Ok(0) => break,
                            Ok(count) => {
                                info!("read {count} bytes of OTA update!");
                                update.write(&buf[..count])?;
                            }
                            Err(_) => {
                                let mut res = req.into_status_response(500)?;
                                res.write_all(b"firmware write failed!")?;
                                res.flush()?;
                                bail!(
                                    "failed to write firmware update to flash!"
                                )
                            }
                        }
                    }

                    let Ok(fin) = update.finish() else {
                        let mut res = req.into_status_response(400)?;
                        res.write_all(b"invalid firmware!")?;
                        res.flush()?;
                        bail!("user submitted invalid firmware!");
                    };

                    let mut res = req.into_ok_response()?;
                    res.write_all(b"update applied, please restart!")?;
                    res.flush()?;
                    info!("update applied!");
                    thread::sleep(Duration::from_secs(5));

                    fin.activate()?;

                    Ok(())
                }
            }
        },
    )?;

    mem::forget(server);
    Ok(())
}
