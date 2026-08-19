//! Two-board ESP32-H2 commissioner-style DTLS demo over Thread IPv6.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::expect_used, clippy::unwrap_used)]

extern crate alloc;

#[cfg(feature = "role-client")]
use alloc::format;
#[cfg(feature = "role-server")]
use alloc::vec::Vec;
use core::{
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    str,
    time::Duration,
};

use embassy_executor::Spawner;
use embassy_time::{Delay, Timer};
use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    rng::{Trng, TrngSource},
    timer::timg::TimerGroup,
};
use esp_println::println;
use esp_radio::ieee802154::Ieee802154;
#[cfg(feature = "role-client")]
use meshcop_dtls::DtlsClient;
#[cfg(feature = "role-server")]
use meshcop_dtls::DtlsServer;
use openthread::{
    DeviceRole, OpenThread, OtResources, OtUdpResources, SimpleRamSettings, UdpSocket,
    esp::EspRadio,
};
use static_cell::StaticCell;
use tinyrlibc as _;

#[cfg(feature = "role-client")]
use crate::config::leader_aloc;
use crate::{
    config::{ACTIVE_DATASET_TLV_HEX, DEMO_PORT, dataset_pskc},
    thread_udp::{ThreadUdp, UDP_RX_BUFFER_SIZE},
};

mod config;
mod thread_udp;

#[cfg(all(feature = "role-server", feature = "role-client"))]
compile_error!("enable exactly one of `role-server` or `role-client`, not both");
#[cfg(not(any(feature = "role-server", feature = "role-client")))]
compile_error!("enable exactly one of `role-server` or `role-client`");

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
const APPLICATION_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(feature = "role-client")]
const CLIENT_RETRY_DELAY: embassy_time::Duration = embassy_time::Duration::from_secs(3);
#[cfg(feature = "role-client")]
const CLIENT_MESSAGE_INTERVAL: embassy_time::Duration = embassy_time::Duration::from_secs(2);
#[cfg(feature = "role-server")]
const SERVER_RETRY_DELAY: embassy_time::Duration = embassy_time::Duration::from_millis(250);
const SETTINGS_BUFFER_SIZE: usize = 2_048;
const UDP_SOCKET_COUNT: usize = 1;

static OT_RNG: StaticCell<Trng> = StaticCell::new();
static OT_RESOURCES: StaticCell<OtResources> = StaticCell::new();
static OT_UDP_RESOURCES: StaticCell<OtUdpResources<UDP_SOCKET_COUNT, UDP_RX_BUFFER_SIZE>> =
    StaticCell::new();
static OT_SETTINGS_BUFFER: StaticCell<[u8; SETTINGS_BUFFER_SIZE]> = StaticCell::new();
static OT_SETTINGS: StaticCell<SimpleRamSettings<'static>> = StaticCell::new();

esp_bootloader_esp_idf::esp_app_desc!();

#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    let hal_config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(hal_config);

    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 64 * 1024);

    let timer_group = TimerGroup::new(peripherals.TIMG0);
    let software_interrupt =
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timer_group.timer0, software_interrupt.software_interrupt0);

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let dtls_rng = match Trng::try_new() {
        Ok(rng) => rng,
        Err(error) => {
            println!("fatal: could not start hardware TRNG: {:?}", error);
            halt().await
        }
    };

    let ot_rng_value = dtls_rng.clone();
    let mut ieee_eui64 = [0; 8];
    ot_rng_value.read(&mut ieee_eui64);

    let ot_rng = OT_RNG.init(ot_rng_value);
    let ot_resources = OT_RESOURCES.init(OtResources::new());
    let ot_udp_resources = OT_UDP_RESOURCES.init(OtUdpResources::new());
    let settings_buffer = OT_SETTINGS_BUFFER.init([0; SETTINGS_BUFFER_SIZE]);
    let ot_settings = OT_SETTINGS.init(SimpleRamSettings::new(settings_buffer));

    let ot = match OpenThread::new_with_udp(
        ieee_eui64,
        ot_rng,
        ot_settings,
        ot_resources,
        ot_udp_resources,
    ) {
        Ok(ot) => ot,
        Err(error) => {
            println!("fatal: could not initialize OpenThread: {}", error);
            halt().await
        }
    };

    let radio = EspRadio::new(Ieee802154::new(peripherals.IEEE802154));
    match run_openthread(ot.clone(), radio) {
        Ok(token) => spawner.spawn(token),
        Err(error) => {
            println!("fatal: could not allocate OpenThread task: {:?}", error);
            halt().await
        }
    }

    #[cfg(feature = "role-server")]
    println!("ESP32-H2 Thread DTLS demo: role=server (FTD)");
    #[cfg(feature = "role-client")]
    println!("ESP32-H2 Thread DTLS demo: role=client (MTD, rx-on)");

    println!("thread: installing canned Active Operational Dataset");
    if let Err(error) = ot.set_active_dataset_tlv_hexstr(ACTIVE_DATASET_TLV_HEX) {
        println!("fatal: could not install Active Operational Dataset: {error}");
        halt().await
    }

    #[cfg(feature = "role-server")]
    {
        if let Err(error) = ot.set_link_mode(true, true, true) {
            println!("fatal: could not configure Full Thread Device mode: {error}");
            halt().await
        }
        if !ot.router_eligible() {
            println!("fatal: server FTD is not router-eligible");
            halt().await
        }
        println!("thread: FTD configured router-eligible");
    }

    #[cfg(feature = "role-client")]
    {
        if let Err(error) = ot.set_link_mode(true, false, false) {
            println!("fatal: could not configure rx-on Minimal Thread Device mode: {error}");
            halt().await
        }
        println!("thread: MTD configured rx-on; MTD builds are never router-eligible");
    }

    if let Err(error) = ot.enable_ipv6(true) {
        println!("fatal: could not bring the Thread IPv6 interface up: {error}");
        halt().await
    }
    println!("thread: IPv6 interface up");

    if let Err(error) = ot.enable_thread(true) {
        println!("fatal: could not start Thread: {error}");
        halt().await
    }
    println!("thread: protocol started");

    #[cfg(feature = "role-server")]
    wait_for_role(&ot, DeviceRole::Leader).await;
    #[cfg(feature = "role-client")]
    wait_for_role(&ot, DeviceRole::Child).await;

    let bind_address = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DEMO_PORT, 0, 0);
    let socket = match UdpSocket::bind(ot, &bind_address) {
        Ok(socket) => socket,
        Err(error) => {
            println!("fatal: could not bind OpenThread UDP port {DEMO_PORT}: {error}");
            halt().await
        }
    };
    let transport = ThreadUdp::new(socket, DEMO_PORT);

    #[cfg(feature = "role-server")]
    run_server(transport, dtls_rng).await;
    #[cfg(feature = "role-client")]
    run_client(transport, dtls_rng).await;
}

#[embassy_executor::task]
async fn run_openthread(ot: OpenThread<'static>, radio: EspRadio<'static>) -> ! {
    ot.run(radio).await
}

async fn wait_for_role(ot: &OpenThread<'_>, wanted: DeviceRole) {
    let mut previous = None;

    loop {
        let role = ot.net_status().role;
        if previous != Some(role) {
            println!("thread: role -> {:?}", role);
            previous = Some(role);
        }
        if role == wanted {
            println!("thread: required role reached: {:?}", wanted);
            return;
        }
        ot.wait_changed().await;
    }
}

#[cfg(feature = "role-server")]
async fn run_server(mut transport: ThreadUdp<'_>, mut rng: Trng) -> ! {
    let local = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DEMO_PORT, 0, 0));
    let pskc = dataset_pskc();
    let mut attempt = 1u32;

    println!("server: Leader UDP socket bound on [::]:{DEMO_PORT}");
    loop {
        println!("server: waiting for client (accept attempt {})", attempt);
        let server = DtlsServer::new(&mut transport, Delay, local);
        match server
            .accept_with_rng(&mut rng, &pskc, HANDSHAKE_TIMEOUT)
            .await
        {
            Ok(mut session) => {
                println!("server: DTLS established with {}", session.peer_addr());
                loop {
                    match session.recv_application_data(APPLICATION_TIMEOUT).await {
                        Ok(payload) => {
                            log_application_payload("server: received", &payload);
                            let mut response = Vec::with_capacity(5 + payload.len());
                            response.extend_from_slice(b"ack: ");
                            response.extend_from_slice(&payload);
                            if let Err(error) = session.send_application_data(&response).await {
                                println!("server: send failed, restarting session: {}", error);
                                break;
                            }
                        }
                        Err(error) => {
                            println!("server: session ended, listening again: {}", error);
                            break;
                        }
                    }
                }
            }
            Err(error) => println!("server: accept attempt failed: {}", error),
        }
        attempt = attempt.wrapping_add(1);
        Timer::after(SERVER_RETRY_DELAY).await;
    }
}

#[cfg(feature = "role-client")]
async fn run_client(mut transport: ThreadUdp<'_>, mut rng: Trng) -> ! {
    let local = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DEMO_PORT, 0, 0));
    let peer = SocketAddr::V6(leader_aloc());
    let pskc = dataset_pskc();
    let mut connection_attempt = 1u32;
    let mut message_counter = 0u32;

    loop {
        println!(
            "client: connecting to Leader ALOC {} (attempt {})",
            peer, connection_attempt
        );
        let client = DtlsClient::new(&mut transport, Delay, local, peer);
        match client
            .connect_with_rng(&mut rng, &pskc, HANDSHAKE_TIMEOUT)
            .await
        {
            Ok(mut session) => {
                println!("client: DTLS established with {}", session.peer_addr());
                loop {
                    Timer::after(CLIENT_MESSAGE_INTERVAL).await;
                    let message = format!("hello {}", message_counter);
                    println!("client: sending {}", message);

                    match session
                        .request_application_data(message.as_bytes(), APPLICATION_TIMEOUT)
                        .await
                    {
                        Ok(response) => {
                            let expected = format!("ack: {}", message);
                            if response == expected.as_bytes() {
                                println!("client: round trip ok: {}", expected);
                            } else {
                                log_application_payload("client: unexpected response", &response);
                            }
                            message_counter = message_counter.wrapping_add(1);
                        }
                        Err(error) => {
                            println!("client: round trip failed, reconnecting: {}", error);
                            break;
                        }
                    }
                }
            }
            Err(error) => println!("client: connect attempt failed: {}", error),
        }
        connection_attempt = connection_attempt.wrapping_add(1);
        Timer::after(CLIENT_RETRY_DELAY).await;
    }
}

fn log_application_payload(prefix: &str, payload: &[u8]) {
    match str::from_utf8(payload) {
        Ok(text) => println!("{}: {}", prefix, text),
        Err(_) => println!(
            "{}: <non-UTF-8 application data, {} bytes>",
            prefix,
            payload.len()
        ),
    }
}

async fn halt() -> ! {
    loop {
        Timer::after(embassy_time::Duration::from_secs(1)).await;
    }
}
