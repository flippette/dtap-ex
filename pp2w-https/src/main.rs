#![no_std]
#![no_main]
#![feature(impl_trait_in_assoc_type, generic_arg_infer)]
#![expect(unstable_features)]

mod error;
mod util;

use core::str;

use defmt_rtt as _;
use panic_probe as _;

use crate::error::{Error, Report};
use cyw43::{JoinAuth, JoinOptions, ScanOptions};
use cyw43_pio::{PioSpi, RM2_CLOCK_DIVIDER};
use defmt::{debug, error, info, intern};
use embassy_executor::{Spawner, main, task};
use embassy_net::{
    StackResources,
    dns::DnsSocket,
    tcp::client::{TcpClient, TcpClientState},
};
use embassy_rp::{
    adc::{self, Adc},
    bind_interrupts,
    block::ImageDef,
    gpio::{Level, Output},
    peripherals::*,
    pio::{self, Pio},
    trng::{self, Trng},
};
use embassy_time::{Duration, Timer, WithTimeout};
use heapless::String;
use reqwless::{
    client::{HttpClient, TlsConfig, TlsVerify},
    request::{Method, RequestBuilder},
    response::Status,
};
use static_cell::{ConstStaticCell, StaticCell};
use ufmt::uwrite;
use ufmt_float::uFmt_f32;

#[used]
#[unsafe(link_section = ".start_block")]
static IMAGE_DEF: ImageDef = ImageDef::secure_exe();

const NET_TIMEOUT: Duration = Duration::from_secs(5);
const NET_COOLDOWN: Duration = Duration::from_secs(30);
const NET_RETRIES: usize = 10;

#[main]
async fn _start(s: Spawner) {
    if let Err(rep) = main(s).await {
        error!("{}", rep.error);
        error!("stacktrace:");
        rep.trace.iter().for_each(|loc| error!("  {}", loc));
        if rep.more {
            error!("  (rest of stacktrace omitted)");
        }

        // basically `panic!` but without dirtying the logs
        cortex_m::asm::udf();
    }

    info!("main exited!");
}

async fn main(s: Spawner) -> Result<(), Report> {
    // ===== initialize the embassy-rp HAL ===== //

    let p = embassy_rp::init(<_>::default());
    info!("HAL init!");

    // ===== initialize the global TRNG ===== //

    let mut trng = Trng::new(p.TRNG, Irqs, <_>::default());

    // ===== initialize the cyw43 driver ===== //

    let (dev, mut ctrl) = {
        let pwr = Output::new(p.PIN_23, Level::Low);
        let cs = Output::new(p.PIN_25, Level::High);
        let mut pio = Pio::new(p.PIO0, Irqs);
        let spi = PioSpi::new(
            &mut pio.common,
            pio.sm0,
            RM2_CLOCK_DIVIDER,
            pio.irq0,
            cs,
            p.PIN_24,
            p.PIN_29,
            p.DMA_CH0,
        );

        let state = {
            static STATE: StaticCell<cyw43::State> = StaticCell::new();
            STATE.init_with(cyw43::State::new)
        };

        let (dev, ctrl, runner) =
            cyw43::new(state, pwr, spi, include_bytes!("../fw/cyw43/fw.bin"))
                .await;
        info!("cyw43 driver init!");

        report!(s.spawn(cyw43_runner(runner)))?;

        (dev, ctrl)
    };

    ctrl.init(include_bytes!("../fw/cyw43/clm.bin")).await;
    ctrl.set_power_management(cyw43::PowerManagementMode::Aggressive)
        .await;
    info!("cyw43 ctrl init!");

    // ===== connect to Wi-Fi ===== //

    let ssid = env!("APP_SSID");
    let pass = env!("APP_PASS");

    info!("scanning for SSID `{=str}`...", ssid);
    let mut aps = ctrl
        .scan({
            let mut opts = ScanOptions::default();
            opts.ssid = ssid.parse().ok();
            opts
        })
        .await;
    while let Some(ap) = aps.next().await {
        info!(
            "found {=u8:02x}:{=u8:02x}:{=u8:02x}:{=u8:02x}:{=u8:02x}:{=u8:02x} ({=i16} dBm)",
            ap.bssid[0],
            ap.bssid[1],
            ap.bssid[2],
            ap.bssid[3],
            ap.bssid[4],
            ap.bssid[5],
            ap.rssi,
        )
    }
    drop(aps);

    info!("joining SSID `{=str}`...", ssid);
    report!(
        ctrl.join(ssid, {
            let mut opts = JoinOptions::default();
            opts.passphrase = pass.as_bytes();
            opts.cipher_aes = !pass.is_empty();
            opts.auth = if pass.is_empty() {
                JoinAuth::Open
            } else {
                JoinAuth::Wpa2Wpa3
            };
            opts
        })
        .await
    )?;
    info!("joined SSID `{=str}`!", ssid);

    // ===== initialize the embassy-net stack ===== //

    let stack = {
        let resources = {
            static STACK_RESOURCES: ConstStaticCell<StackResources<3>> =
                ConstStaticCell::new(StackResources::new());
            STACK_RESOURCES.take()
        };

        let (stack, runner) = embassy_net::new(
            dev,
            embassy_net::Config::dhcpv4(<_>::default()),
            resources,
            trng.blocking_next_u64(),
        );
        info!("embassy-net stack init!");

        report!(s.spawn(embassy_net_runner(runner)))?;

        stack
    };

    // ===== wait for DHCP configuration ===== //

    info!("waiting for DHCP configuration...");
    report!(
        util::with_retries(
            || stack.wait_config_up().with_timeout(NET_TIMEOUT),
            NET_RETRIES,
        )
        .await
    )?;
    info!("DHCP configuration complete!");

    // ===== initialize HTTP client ===== //

    let http_buf = {
        static BUFFER: ConstStaticCell<[u8; 65536]> =
            ConstStaticCell::new([0; _]);
        BUFFER.take()
    };
    let mut http = {
        static TCP_STATE: ConstStaticCell<TcpClientState<1, 1024, 1024>> =
            ConstStaticCell::new(TcpClientState::new());
        static TCP_CLIENT: StaticCell<TcpClient<'static, 1, 1024, 1024>> =
            StaticCell::new();
        static DNS_SOCKET: StaticCell<DnsSocket<'static>> = StaticCell::new();
        static TLS_READ_BUF: ConstStaticCell<[u8; 16640]> =
            ConstStaticCell::new([0; _]);
        static TLS_WRITE_BUF: ConstStaticCell<[u8; 16640]> =
            ConstStaticCell::new([0; _]);

        HttpClient::new_with_tls(
            TCP_CLIENT.init_with(|| TcpClient::new(stack, TCP_STATE.take())),
            DNS_SOCKET.init_with(|| DnsSocket::new(stack)),
            TlsConfig::new(
                trng.blocking_next_u64(),
                TLS_READ_BUF.take(),
                TLS_WRITE_BUF.take(),
                TlsVerify::None,
            ),
        )
    };
    info!("HTTP client init!");

    // ===== initialize temperature sensor ===== //

    let mut adc = Adc::new(p.ADC, Irqs, <_>::default());
    let mut sensor = adc::Channel::new_temp_sensor(p.ADC_TEMP_SENSOR);

    'api: loop {
        // ===== API connectivity test ===== //

        let host = env!("APP_API_HOST");
        let pass = env!("APP_API_PASS");
        let uuid = env!("APP_API_UUID");

        let mut req = report!({
            let mut i = 0;

            loop {
                match http
                    .request(Method::GET, host)
                    .with_timeout(NET_TIMEOUT)
                    .await
                {
                    Ok(Ok(req)) => break Ok::<_, Error>(req),
                    Ok(Err(err)) if i == NET_RETRIES - 1 => {
                        error!("{}", err);
                        Timer::after(NET_COOLDOWN).await;
                        continue 'api;
                    }
                    Err(err) if i == NET_RETRIES - 1 => {
                        error!("{}", err);
                        Timer::after(NET_COOLDOWN).await;
                        continue 'api;
                    }
                    _ => {
                        i += 1;
                        Timer::after(NET_COOLDOWN).await;
                    }
                }
            }
        })?
        .path("/ping");

        let res = report!({
            let mut i = 0;

            loop {
                match req.send(http_buf).with_timeout(NET_TIMEOUT).await {
                    Ok(Ok(res)) => break Ok::<_, Error>(res),
                    Ok(Err(err)) if i == NET_RETRIES - 1 => {
                        error!("{}", err);
                        Timer::after(NET_COOLDOWN).await;
                        continue 'api;
                    }
                    Err(err) if i == NET_RETRIES - 1 => {
                        error!("{}", err);
                        Timer::after(NET_COOLDOWN).await;
                        continue 'api;
                    }
                    _ => {
                        i += 1;
                        Timer::after(NET_COOLDOWN).await;
                    }
                }
            }
        })?;

        match res.status.into() {
            Status::Ok => info!("we have API connectivity!"),
            other => {
                error!("API connectivity test failed: {}", other);
                return report!(Err(Error::from(intern!(
                    "API connectivity test failed"
                ))));
            }
        }

        drop(req);

        // first read seems to have significant error, do this so we get better
        // values in the upload loop
        report!(adc.read(&mut sensor).await)?;
        info!("waiting for ADC temp sensor to stabilize...");
        Timer::after_secs(10).await;

        // ===== upload readings ===== //

        'upload: loop {
            let temp = {
                let raw = report!(adc.read(&mut sensor).await)?;

                // see chapter 12.4.6 of the RP2350 datasheet for the formula
                // IOVDD on my board seems to have drifted a bit, usually it's 3.3V
                27.0 - (f32::from(raw) * 3.375 / 4096.0 - 0.706) / 0.001721
            };

            let mut path = String::<128>::new();
            report!(
                uwrite!(
                    path,
                    "/add?uuid={}&pass={}&reading={}",
                    uuid,
                    pass,
                    uFmt_f32::One(temp)
                )
                .map_err(|()| Error::AdHoc(intern!("path overflow!")))
            )?;

            let mut req = report!({
                let mut i = 0;

                loop {
                    match http
                        .request(Method::GET, host)
                        .with_timeout(NET_TIMEOUT)
                        .await
                    {
                        Ok(Ok(req)) => break Ok::<_, Error>(req),
                        Ok(Err(err)) if i == NET_RETRIES - 1 => {
                            error!("{}", err);
                            Timer::after(NET_COOLDOWN).await;
                            continue 'api;
                        }
                        Err(err) if i == NET_RETRIES - 1 => {
                            error!("{}", err);
                            Timer::after(NET_COOLDOWN).await;
                            continue 'upload;
                        }
                        _ => {
                            i += 1;
                            Timer::after(NET_COOLDOWN).await;
                        }
                    }
                }
            })?
            .path(&path);

            let res = report!({
                let mut i = 0;

                loop {
                    match req.send(http_buf).with_timeout(NET_TIMEOUT).await {
                        Ok(Ok(res)) => break Ok::<_, Error>(res),
                        Ok(Err(err)) if i == NET_RETRIES - 1 => {
                            error!("{}", err);
                            Timer::after(NET_COOLDOWN).await;
                            continue 'api;
                        }
                        Err(err) if i == NET_RETRIES - 1 => {
                            error!("{}", err);
                            Timer::after(NET_COOLDOWN).await;
                            continue 'upload;
                        }
                        _ => {
                            i += 1;
                            Timer::after(NET_COOLDOWN).await;
                        }
                    }
                }
            })?;

            info!("");
            info!("===== response headers:");
            info!("status: {}", Status::from(res.status));
            info!("headers:");
            res.headers()
                .filter(|(k, _)| !k.is_empty())
                .for_each(|(k, v)| match str::from_utf8(v) {
                    Ok(v) => info!("  {=str}: {=str}", k, v),
                    Err(_) => info!("  {=str}: <invalid UTF-8> {=[u8]}", k, v),
                });

            let body = match res
                .body()
                .read_to_end()
                .with_timeout(NET_TIMEOUT)
                .await
            {
                Ok(Ok(body)) => body,
                Ok(Err(err)) => {
                    error!("{}", err);
                    continue 'upload;
                }
                Err(err) => {
                    error!("{}", err);
                    continue 'upload;
                }
            };

            info!("===== response body ({=usize} bytes):", body.len());
            debug!("body = {=[u8]}", body);
            match str::from_utf8(body) {
                _ if body.is_empty() => info!("<empty>"),
                Ok(s) => s.lines().for_each(|s| info!("{=str}", s)),
                Err(_) => info!(
                    "<invalid UTF-8> {=[u8]} (+{=usize} bytes)",
                    &body[..body.len().min(64)],
                    body.len().saturating_sub(64),
                ),
            }
            info!("===== response end");

            Timer::after(NET_COOLDOWN).await;
        }
    }
}

bind_interrupts! {
    struct Irqs {
        PIO0_IRQ_0 => pio::InterruptHandler<PIO0>;
        TRNG_IRQ => trng::InterruptHandler<TRNG>;
        ADC_IRQ_FIFO => adc::InterruptHandler;
    }
}

#[task]
async fn cyw43_runner(
    runner: cyw43::Runner<
        'static,
        Output<'static>,
        PioSpi<'static, PIO0, 0, DMA_CH0>,
    >,
) -> ! {
    info!("cyw43 runner started!");
    runner.run().await
}

#[task]
async fn embassy_net_runner(
    mut runner: embassy_net::Runner<'static, cyw43::NetDriver<'static>>,
) -> ! {
    info!("embassy-net stack runner spawned!");
    runner.run().await
}
