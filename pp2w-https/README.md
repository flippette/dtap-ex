# pp2w-https

Implementation of Exercise 3 "Wireless data transfer (to/from the _ESP32_)" for
the _Pimoroni Pico Plus 2 W_ (because that's what I have at home).

## Building

First, you will need to install
[`flip-link`](https://github.com/knurling-rs/flip-link) and
[`probe-rs`](https://github.com/probe-rs/probe-rs).

There are several configuration options in `.cargo/config.toml` omitted on
purpose:

- `APP_SSID`: The SSID we attempt to connect to.
- `APP_PASS`: The password for the SSID above.
- `APP_API_HOST`: The remote host that serves the API.
- `APP_API_PASS`: The required `pass` query parameter of the `/add` endpoint.
- `APP_API_UUID`: The required `uuid` query parameter of the `/add` endpoint.

Once you set them, then the code will build and you can flash it on a Pico Plus
2 W with `cargo run --release`.

Note that you can also set these options as environment variables (that's what
I did) and doing it this way will override options set in the file.
