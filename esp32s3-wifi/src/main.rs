#![no_std]
#![no_main]
#![feature(impl_trait_in_assoc_type)]

use defmt::{error, info, Debug2Format};
use defmt_rtt as _;
use embassy_executor::{task, Spawner};
use embassy_net::StackResources;
use embassy_time::Timer;
use esp_backtrace as _;
use esp_hal::{rng::Rng, timer::timg::TimerGroup};
use esp_hal_embassy::main;
use esp_wifi::{
    wifi::{
        self, WifiController, WifiDevice, WifiEvent, WifiStaDevice, WifiState,
    },
    EspWifiController,
};
use static_cell::{ConstStaticCell, StaticCell};

const SSID: &str = "aalto open";
const PASSWD: &str = "";

#[main]
async fn main(s: Spawner) {
    let p = esp_hal::init(<_>::default());
    let timg0 = TimerGroup::new(p.TIMG0);
    esp_hal_embassy::init(timg0.timer0);
    esp_alloc::heap_allocator!(256 * 1024);

    info!("init!");

    static CTRL: StaticCell<EspWifiController<'static>> = StaticCell::new();
    let mut rng = Rng::new(p.RNG);
    let wifi = CTRL.init(
        esp_wifi::init(timg0.timer1, rng, p.RADIO_CLK)
            .expect("failed to init wifi ctrl"),
    );

    info!("wifi ctrl init!");

    let (iface, ctrl) = wifi::new_with_mode(wifi, p.WIFI, WifiStaDevice)
        .expect("failed to init wifi iface");

    info!("wifi iface init!");

    static NETRES: ConstStaticCell<StackResources<3>> =
        ConstStaticCell::new(StackResources::new());
    let netcfg = embassy_net::Config::dhcpv4(<_>::default());
    let seed = (rng.random() as u64) << 32 | rng.random() as u64;
    let (stack, runner) = embassy_net::new(iface, netcfg, NETRES.take(), seed);

    s.must_spawn(conn(ctrl));
    s.must_spawn(net_task(runner));

    info!("net stack init!");

    while !stack.is_link_up() {
        Timer::after_millis(500).await;
    }

    info!("net link up!");
    info!("waiting for net stack cfg!");

    loop {
        if let Some(cfg) = stack.config_v4() {
            info!(
                "got net stack cfg: ip addr = {}, gateway = {}, dns = {}",
                cfg.address, cfg.gateway, cfg.dns_servers
            );

            break;
        }

        Timer::after_millis(500).await;
    }

    info!("main task done!");
}

#[task]
async fn conn(mut ctrl: WifiController<'static>) {
    info!("conn task init!");
    if let Ok(caps) = ctrl.capabilities() {
        info!("ctrl caps: {}", Debug2Format(&caps));
    }

    loop {
        if let WifiState::StaConnected = wifi::wifi_state() {
            ctrl.wait_for_event(WifiEvent::StaDisconnected).await;
            info!("got disconnect event, reconnecting!");
            Timer::after_millis(500).await;
        }

        if !matches!(ctrl.is_started(), Ok(true)) {
            info!("wifi ctrl starting!");
            ctrl.start_async().await.expect("failed to start wifi ctrl");
            info!("wifi ctrl started!");
        }

        loop {
            info!("wifi ctrl scanning!");
            match ctrl.scan_n_async::<16>().await {
                Ok((aps, count)) => {
                    info!("heard from {} aps, selected {}:", count, aps.len());
                    aps.iter().enumerate().for_each(|(i, ap)| {
                        info!(
                            "{}. {} (auth = {}, rssi = {})",
                            i + 1,
                            ap.ssid,
                            ap.auth_method.unwrap_or_default(),
                            ap.signal_strength
                        )
                    });

                    match aps.iter().find(|ap| ap.ssid.as_str() == SSID) {
                        Some(ap) => {
                            info!("found wanted ap, connecting!");
                            ctrl.set_configuration(
                                &wifi::Configuration::Client(
                                    wifi::ClientConfiguration {
                                        ssid: ap.ssid.clone(),
                                        bssid: Some(ap.bssid),
                                        auth_method: ap
                                            .auth_method
                                            .unwrap_or_default(),
                                        password: PASSWD
                                            .try_into()
                                            .expect("password too long"),
                                        channel: None,
                                    },
                                ),
                            )
                            .expect("failed to set wifi ctrl cfg");
                            info!("wifi ctrl cfg set!");
                            break;
                        }
                        None => {
                            error!("didn't find wanted ap, retrying soon!");
                            Timer::after_secs(5).await;
                        }
                    }
                }
                Err(err) => {
                    error!("wifi ctrl failed to scan, retrying soon: {}", err);
                    Timer::after_secs(5).await;
                }
            }
        }

        info!("wifi ctrl connecting!");

        match ctrl.connect_async().await {
            Ok(_) => info!("wifi ctrl connected!"),
            Err(err) => {
                error!("wifi ctrl failed to connect, will retry soon: {}", err);
                Timer::after_secs(5).await;
            }
        }
    }
}

#[task]
async fn net_task(
    mut runner: embassy_net::Runner<
        'static,
        WifiDevice<'static, WifiStaDevice>,
    >,
) {
    runner.run().await;
}
