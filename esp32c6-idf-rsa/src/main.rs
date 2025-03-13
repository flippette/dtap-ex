mod rsa;
mod wrap;

use std::{array, ffi::CStr, mem::ManuallyDrop, thread, time::Duration};

use anyhow::{Result, anyhow, ensure};
use base64::prelude::*;
use embedded_svc::{http::client::Client as HttpClient, utils};
use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    hal::prelude::*,
    http::{self, client::EspHttpConnection},
    log::EspLogger,
    nvs::{EspDefaultNvsPartition, EspNvs},
    sys,
    wifi::{self, BlockingWifi, EspWifi, WifiDeviceId},
};
use log::{error, info};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use rsa::Rsa;
use wrap::ErrorCode;

const SSID: &str = env!("APP_SSID");
const PASS: &str = env!("APP_PASS");
const AUTH: wifi::AuthMethod = match PASS {
    s if s.is_empty() => wifi::AuthMethod::None,
    _ => wifi::AuthMethod::WPA2WPA3Personal,
};

const API_HOST: &str = env!("APP_API_HOST");

const SERVER_PUBKEY: &[u8] = include_bytes!("../keys/spub.pem");

fn main() -> Result<()> {
    sys::link_patches();
    EspLogger::initialize_default();
    info!("HAL init!");

    let peri = Peripherals::take()?;
    let sysl = EspSystemEventLoop::take()?;
    let nvsp = EspDefaultNvsPartition::take()?;

    let mut wifi = ManuallyDrop::new(BlockingWifi::wrap(
        EspWifi::new(peri.modem, sysl.clone(), Some(nvsp.clone()))?,
        sysl,
    )?);
    wifi_connect(&mut wifi, SSID, PASS, AUTH)?;
    info!("Wi-Fi set up!");
    info!(
        "device UUID: {}",
        base16::encode_lower(&wifi.wifi().get_mac(WifiDeviceId::Sta)?)
    );

    unsafe { ensure!(sys::psa_crypto_init() == 0, "PSA crypto init failed!") }
    let mut rsa = get_rsa::<1024>(nvsp.clone())?;
    info!("retrieved RSA keys!");

    let plaintext = "why do they call it oven when you of in the cold food of out hot eat the food";
    info!("plaintext:   {:?}", plaintext);
    info!("...as bytes: {:02x?}", plaintext.as_bytes());
    let ciphertext = rsa.encrypt_to_vec(plaintext.as_bytes())?;
    info!("ciphertext:  {:02x?}", ciphertext);
    let plaintext = rsa.decrypt_to_vec(&ciphertext)?;
    info!("plaintext:   {:02x?}", plaintext);
    info!("...as UTF-8: {:?}", String::from_utf8_lossy(&plaintext));

    let mut http = HttpClient::wrap(EspHttpConnection::new(
        &http::client::Configuration {
            crt_bundle_attach: Some(sys::esp_crt_bundle_attach),
            ..<_>::default()
        },
    )?);
    info!("created HTTP client!");

    info!("stage 1: handshake init");

    let session_id = base16::encode_lower(&rand::random::<[u8; 16]>());
    let uuid = base16::encode_lower(&wifi.wifi().get_mac(WifiDeviceId::Sta)?);

    let uri = format!(
        "{API_HOST}/handshake?action=initiate&session_id={}&uuid={}",
        session_id, uuid
    );
    info!("init URI: {uri}");
    let req = http.get(&uri)?;
    let res = req.submit()?;
    info!("got handshake init response!");

    let mut buf = vec![0; 1024];
    let len = utils::io::try_read_full(res, &mut buf).map_err(|e| e.0)?;
    info!("read response of {} bytes", len);
    let buf = &buf[..len];

    let n1 = serde_json::from_slice::<serde_json::Value>(buf)?
        .as_object()
        .and_then(|val| val.get("n1"))
        .and_then(|val| val.as_str())
        .map(ToString::to_string)
        .ok_or_else(|| anyhow!("failed to decode handshake init response!"))?;
    info!("server n1: {n1:?}");

    info!("stage 2: handshake challenge-response");

    let n1 = base16::decode(&n1)?;
    info!("server n1 as base16: {:02x?}", n1);
    let sig = BASE64_STANDARD.encode(rsa.sign_to_vec(&n1)?);
    info!("signature: {:?}", sig);
    let n2 = base16::encode_lower(&rand::random::<[u8; 16]>());

    let uri = format!(
        "{API_HOST}/handshake?action=respond&session_id={}&uuid={}&signature={}&n2={}",
        session_id,
        uuid,
        utf8_percent_encode(&sig, NON_ALPHANUMERIC),
        n2
    );
    info!("challenge-response URI: {uri}");
    let req = http.get(&uri)?;
    let res = req.submit()?;
    info!("got handshake challenge-response response!");

    let mut buf = vec![0; 1024];
    let len = utils::io::try_read_full(res, &mut buf).map_err(|e| e.0)?;
    info!("read response of {} bytes", len);
    let buf = &buf[..len];
    info!(
        "(challenge-response response: {:?})",
        String::from_utf8_lossy(buf)
    );

    let sig = serde_json::from_slice::<serde_json::Value>(buf)?
        .as_object()
        .and_then(|val| val.get("signature"))
        .and_then(|val| val.as_str())
        .map(ToString::to_string)
        .ok_or_else(|| {
            anyhow!("failed to decode handshake challenge-response response!")
        })?;
    info!("server n2 sig: {:?}", sig);

    let sig = BASE64_STANDARD.decode(sig)?;
    let server_pk = unsafe {
        let mut tmp =
            wrap::Wrapped::new(sys::mbedtls_pk_init, sys::mbedtls_pk_free);
        sys::mbedtls_pk_setup(
            &raw mut *tmp,
            sys::mbedtls_pk_info_from_type(
                sys::mbedtls_pk_type_t_MBEDTLS_PK_RSA,
            ),
        )
        .into_result(0, rsa::Error::PkSetup)?;
        sys::mbedtls_pk_parse_public_key(
            &raw mut *tmp,
            SERVER_PUBKEY.as_ptr(),
            SERVER_PUBKEY.len(),
        )
        .into_result(0, rsa::Error::PkParsePublicKey)?;
        tmp
    };
    rsa::verify(&server_pk, n2.as_bytes(), &sig)?;

    info!("handshake succeeded!");

    Ok(())
}

/// Get/generate and store RSA keys into NVS.
fn get_rsa<const BITS: u16>(nvsp: EspDefaultNvsPartition) -> Result<Rsa<BITS>>
where
    Rsa<BITS>: rsa::SupportedLength,
{
    let mut nvs = EspNvs::new(nvsp, "rsa", true)?;

    let mut seed: [u8; 65] = array::from_fn(|_| rand::random_range(32..=126));
    seed[64] = 0;

    let mut rsa = Rsa::new(CStr::from_bytes_until_nul(&seed)?)?;
    info!("RSA context init, importing keys...");

    let mut n = vec![0; BITS as usize / 8];
    let n = nvs.get_raw("rsa_n", &mut n)?;
    let mut d = vec![0; BITS as usize / 8];
    let d = nvs.get_raw("rsa_d", &mut d)?;
    let mut e = vec![0; BITS as usize / 8];
    let e = nvs.get_raw("rsa_e", &mut e)?;

    let mut imported = false;
    match (n, d, e) {
        (Some(n), Some(d), Some(e)) => match rsa::Keys::read(n, d, e) {
            Ok(keys) => match rsa.import_keys(keys) {
                Ok(()) => {
                    info!("RSA keys imported!");
                    imported = true;
                }
                Err(err) => error!("RSA keys failed to import: {err}"),
            },
            Err(err) => error!("RSA keys failed to read: {err}"),
        },
        _ => error!("RSA keys do not exist in NVS!"),
    }

    if !imported {
        info!("RSA import failed, generating keys...");

        rsa.generate_keys()?;
        info!("RSA keys generated!");
    }

    info!("writing RSA public key to PEM...");
    let keys = rsa.export()?;
    let pem = keys.write_pubkey_to_vec_pem()?;
    info!("PEM-encoded public key:");
    String::from_utf8_lossy(&pem)
        .lines()
        .for_each(|s| info!("{s}"));

    if !imported {
        info!("saving RSA keys to NVS...");
        let (n, d, e) = keys.write_to_vec()?;
        nvs.set_raw("rsa_n", &n)?;
        nvs.set_raw("rsa_d", &d)?;
        nvs.set_raw("rsa_e", &e)?;
        info!("wrote RSA keys to NVS!");
    }

    Ok(rsa)
}

/// Connect to Wi-Fi.
fn wifi_connect(
    wifi: &mut BlockingWifi<EspWifi<'_>>,
    ssid: &str,
    password: &str,
    auth_method: wifi::AuthMethod,
) -> Result<()> {
    wifi.set_configuration(&wifi::Configuration::Client(
        wifi::ClientConfiguration {
            ssid: ssid.parse().map_err(|_| anyhow!("SSID too long!"))?,
            auth_method,
            password: password
                .parse()
                .map_err(|_| anyhow!("password too long!"))?,
            ..<_>::default()
        },
    ))?;
    info!("Wi-Fi config set!");

    wifi.start()?;
    info!("Wi-Fi started, connecting...");

    while wifi.connect().is_err() {
        error!("Wi-Fi connect failed, retrying...");
        thread::sleep(Duration::from_secs(1));
    }
    info!("Wi-Fi connected!");

    wifi.wait_netif_up()?;
    info!("Wi-Fi link up!");

    Ok(())
}
