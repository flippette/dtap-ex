#![no_std]
#![no_main]
#![feature(impl_trait_in_assoc_type, generic_arg_infer)]
#![expect(unstable_features)]

mod error;
mod panic;
mod upload;
mod util;

use defmt_rtt as _;
use panic_probe as _;

use crate::error::Report;
use cyw43::{JoinAuth, JoinOptions, ScanOptions};
use cyw43_pio::{PioSpi, RM2_CLOCK_DIVIDER};
use defmt::{error, info};
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
use embassy_time::{Duration, WithTimeout};
use reqwless::client::{HttpClient, TlsConfig, TlsVerify};
use static_cell::{ConstStaticCell, StaticCell};

#[used]
#[unsafe(link_section = ".start_block")]
static IMAGE_DEF: ImageDef = ImageDef::secure_exe();

const NET_TIMEOUT: Duration = Duration::from_secs(5);
const NET_COOLDOWN: Duration = Duration::from_secs(30);
const NET_RETRIES: usize = 10;

#[main]
async fn _start(s: Spawner) {
    if let Err(rep) = main(s).await {
        panic!(rep);
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

    let http = {
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

    let adc = Adc::new(p.ADC, Irqs, <_>::default());
    let sensor = adc::Channel::new_temp_sensor(p.ADC_TEMP_SENSOR);

    // ===== spawn upload task ===== //

    report!(s.spawn(upload::task(http, adc, sensor)))?;

    Ok(())
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
