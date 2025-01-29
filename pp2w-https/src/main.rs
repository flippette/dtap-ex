#![no_std]
#![no_main]
#![feature(impl_trait_in_assoc_type, generic_arg_infer)]
#![expect(unstable_features)]

mod error;
mod util;

use core::str;

use defmt_rtt as _;
use panic_probe as _;

use crate::error::Error;
use cyw43::{JoinAuth, JoinOptions};
use cyw43_pio::{PioSpi, RM2_CLOCK_DIVIDER};
use defmt::{debug, error, info, intern};
use embassy_executor::{Spawner, main, task};
use embassy_net::{
    StackResources,
    dns::DnsSocket,
    tcp::client::{TcpClient, TcpClientState},
};
use embassy_rp::{
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

const NET_TIMEOUT: Duration = Duration::from_secs(3);
const NET_RETRIES: usize = 10;

#[main]
async fn _start(s: Spawner) {
    if let Err(err) = main(s).await {
        error!("main returned error: {}", err);
        return;
    }

    info!("main exited!");
}

async fn main(s: Spawner) -> Result<(), Error> {
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

        s.spawn(cyw43_runner(runner))?;

        (dev, ctrl)
    };

    ctrl.init(include_bytes!("../fw/cyw43/clm.bin")).await;
    ctrl.set_power_management(cyw43::PowerManagementMode::Aggressive)
        .await;
    info!("cyw43 ctrl init!");

    // ===== connect to Wi-Fi ===== //

    let ssid = env!("APP_SSID");
    let pass = env!("APP_PASS");

    ctrl.join(ssid, {
        let mut opts = JoinOptions::default();
        opts.passphrase = pass.as_bytes();
        opts.auth = if pass.is_empty() {
            JoinAuth::Open
        } else {
            JoinAuth::Wpa2Wpa3
        };
        opts
    })
    .await?;
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

        s.spawn(embassy_net_runner(runner))?;

        stack
    };

    // ===== wait for DHCP configuration ===== //

    info!("waiting for DHCP configuration...");
    util::with_retries(
        || stack.wait_config_up().with_timeout(NET_TIMEOUT),
        NET_RETRIES,
    )
    .await?;
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

    // ===== API connectivity test ===== //

    let host = env!("APP_API_HOST");
    let pass = env!("APP_API_PASS");
    let uuid = env!("APP_API_UUID");

    let mut req = {
        let mut i = 0;

        loop {
            match http
                .request(Method::GET, host)
                .with_timeout(NET_TIMEOUT)
                .await
            {
                Ok(Ok(req)) => break Ok(req),
                Ok(Err(err)) if i == NET_RETRIES - 1 => {
                    break Err(Error::from(err));
                }
                Err(err) if i == NET_RETRIES - 1 => {
                    break Err(Error::from(err));
                }
                _ => i += 1,
            }
        }
    }?
    .path("/ping");

    let res = {
        let mut i = 0;

        loop {
            match req.send(http_buf).with_timeout(NET_TIMEOUT).await {
                Ok(Ok(res)) => break Ok(res),
                Ok(Err(err)) if i == NET_RETRIES - 1 => {
                    break Err(Error::from(err));
                }
                Err(err) if i == NET_RETRIES - 1 => {
                    break Err(Error::from(err));
                }
                _ => i += 1,
            }
        }
    }?;

    match res.status.into() {
        Status::Ok => info!("we have API connectivity!"),
        other => {
            error!("API connectivity test failed: {}", other);
            return Err(intern!("API connectivity test failed").into());
        }
    }

    drop(req);

    // ===== upload readings ===== //

    loop {
        let temp =
            trng.blocking_next_u32() as f32 / u32::MAX as f32 * 40.0 - 10.0;

        let mut path = String::<128>::new();
        uwrite!(
            path,
            "/add?uuid={}&pass={}&reading={}",
            uuid,
            pass,
            uFmt_f32::One(temp)
        )
        .map_err(|()| Error::AdHoc(intern!("path overflow!")))?;

        let mut req = {
            let mut i = 0;

            loop {
                match http
                    .request(Method::GET, host)
                    .with_timeout(NET_TIMEOUT)
                    .await
                {
                    Ok(Ok(req)) => break Ok(req),
                    Ok(Err(err)) if i == NET_RETRIES - 1 => {
                        break Err(Error::from(err));
                    }
                    Err(err) if i == NET_RETRIES - 1 => {
                        break Err(Error::from(err));
                    }
                    _ => i += 1,
                }
            }
        }?
        .path(&path);

        let res = {
            let mut i = 0;

            loop {
                match req.send(http_buf).with_timeout(NET_TIMEOUT).await {
                    Ok(Ok(res)) => break Ok(res),
                    Ok(Err(err)) if i == NET_RETRIES - 1 => {
                        break Err(Error::from(err));
                    }
                    Err(err) if i == NET_RETRIES - 1 => {
                        break Err(Error::from(err));
                    }
                    _ => i += 1,
                }
            }
        }?;

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
        let body = res.body().read_to_end().await?;
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

        Timer::after_secs(10).await;
    }
}

bind_interrupts! {
    struct Irqs {
        PIO0_IRQ_0 => pio::InterruptHandler<PIO0>;
        TRNG_IRQ => trng::InterruptHandler<TRNG>;
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
