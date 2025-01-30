//! measurement upload task.

use core::str;

use crate::{
    NET_COOLDOWN, NET_RETRIES, NET_TIMEOUT,
    error::{Error, Report},
    panic, report,
};
use defmt::{error, info, intern};
use embassy_executor::task;
use embassy_net::{dns::DnsSocket, tcp::client::TcpClient};
use embassy_rp::adc::{self, Adc};
use embassy_time::{Timer, WithTimeout};
use heapless::String;
use reqwless::{
    client::HttpClient,
    request::{Method, RequestBuilder},
    response::Status,
};
use static_cell::ConstStaticCell;
use ufmt::uwrite;
use ufmt_float::uFmt_f32;

#[task]
pub async fn task(
    http: HttpClient<
        'static,
        TcpClient<'static, 1, 1024, 1024>,
        DnsSocket<'static>,
    >,
    adc: Adc<'static, adc::Async>,
    sensor: adc::Channel<'static>,
) {
    info!("upload task spawned!");

    if let Err(rep) = uploader(http, adc, sensor).await {
        panic!(rep);
    }

    info!("upload task exited!");
}

async fn uploader(
    mut http: HttpClient<
        'static,
        TcpClient<'static, 1, 1024, 1024>,
        DnsSocket<'static>,
    >,
    mut adc: Adc<'static, adc::Async>,
    mut sensor: adc::Channel<'static>,
) -> Result<(), Report> {
    let http_buf = {
        static BUFFER: ConstStaticCell<[u8; 65536]> =
            ConstStaticCell::new([0; _]);
        BUFFER.take()
    };

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
