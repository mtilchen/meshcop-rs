# Mesh Five-O ESP32-H2 Thread IPv6 DTLS demo

This firmware forms a real, two-node Thread network and runs this repository's
Mesh Five-O DTLS client and server (`mesh50-dtls`) over OpenThread native IPv6
UDP sockets:

- `role-server` is a router-eligible Full Thread Device (FTD). It installs the
  canned Active Operational Dataset, forms the partition, becomes Leader, and
  only then starts the DTLS server.
- `role-client` is an rx-on Minimal Thread Device (MTD). It installs the same
  dataset, attaches to the Leader as a child End Device, and only then starts
  the DTLS client.
- The client sends `hello N`; the Leader replies with `ack: hello N` over the
  established DTLS session.

This is a commissioner-style session: Mesh Five-O's DTLS crate performs its Thread
PSKc/EC-JPAKE DTLS handshake using the PSKc taken directly from the installed
dataset. The PSKc, Network Key, derived keys, and raw handshake data are never
logged. All compiled-in credentials are public, desk-demo credentials and must
not be reused.

OpenThread supplies the real Thread IPv6, 6LoWPAN, mesh routing, MAC security,
and device-role machinery. There is no application fragmentation shim and no
synthetic IPv4 addressing.

## Thread binding and build prerequisites

The demo pins the maintained
[`esp-rs/openthread`](https://github.com/esp-rs/openthread) project at commit
`e4d27b39f01563c98fd1e88ab2fa9799a1ae26fe`. Its Cargo package versions are
`openthread 0.2.0` and `openthread-sys 0.2.1`. This revision's ESP example
targets both ESP32-C6 and ESP32-H2, uses `esp-radio 0.18`, `esp-hal 1.1`, and
Embassy, and provides safe native UDP and router-eligibility APIs. The server
feature selects OpenThread's FTD archive; the client selects its default MTD
archive.

The OpenThread C core arrives through `openthread-sys` in this firmware-only,
excluded workspace. The repository's library workspace remains pure Rust and
does not acquire an OpenThread or C dependency.

Install stable Rust, the H2 target, and `espflash`:

```console
rustup target add riscv32imac-unknown-none-elf
cargo install espflash
```

The demo intentionally avoids `build-std`, so it builds with the stable
toolchain's prebuilt `core`/`alloc` for this target; nightly and `rust-src`
are not required.

The pinned default OpenThread configuration has checked-in
`riscv32imac-unknown-none-elf` bindings and prebuilt archives. A verified cold
build did not invoke Clang, CMake, Ninja, or a cross-GCC toolchain. It did need
network access to fetch crates, the pinned Git repository, and its upstream
OpenThread submodule. Thus, beyond the rustup-installed target/components,
there is no additional host build tool; `espflash` is needed only to flash and
monitor hardware.

Changing OpenThread feature knobs or forcing binding generation can invalidate
those prebuilt artifacts. That unsupported customization path performs an
on-the-fly C build and requires Clang, CMake, and Ninja.

## Canned Active Operational Dataset

The dataset is encoded as one TLV hex constant in `src/config.rs`. It was
generated with this repository's own `Dataset` and typed TLV value builders:

```console
cargo run -p mesh50 --example generate_esp32h2_demo_dataset
```

Run that command from the repository root. It prints the complete demo dataset,
including demo-only key material, so do not use its output in production logs.

| Field | Value |
| --- | --- |
| Network name | `mesh50-dtls-demo` |
| Channel | 15 |
| PAN ID | `0xd71d` |
| Extended PAN ID | `02240723d715a10c` |
| Mesh-local prefix | `fd24:723:d715::/64` |
| Active Timestamp | 1, authoritative |
| Security Policy rotation | 672 hours |
| Network Key / PSKc | compiled-in demo-only values |

The firmware decodes both the DTLS PSKc and mesh-local prefix from that same
constant, avoiding duplicate values that could drift.

## IPv6 addressing

Both roles bind OpenThread native UDP port `49191`. The client sends to the
Thread Leader Anycast Locator (ALOC):

```text
fd24:723:d715::ff:fe00:fc00
```

Thread constructs this as `<mesh-local-prefix>:0:ff:fe00:fc00`; ALOC16
`0xfc00` identifies the partition Leader. It is deterministic here because the
server is the only router-capable node. The client is an MTD and can only
attach as a child, so no discovery protocol is needed.

`src/thread_udp.rs` implements `embedded_nal_async::UnconnectedUdp` over
OpenThread's native `UdpSocket`. It accepts and returns genuine
`SocketAddrV6` values. OpenThread and 6LoWPAN handle packets below that adapter.

## Build, flash, and monitor

Build each role from this directory. Exactly one role feature must be enabled:

```console
cargo build --release --features role-server
cargo build --release --features role-client
```

Flash the server first and leave its monitor open until it reports `Leader`:

```console
cargo build --release --features role-server
espflash flash --monitor --chip esp32h2 \
  target/riscv32imac-unknown-none-elf/release/esp32h2-dtls-demo
```

Then build and flash the client:

```console
cargo build --release --features role-client
espflash flash --monitor --chip esp32h2 \
  target/riscv32imac-unknown-none-elf/release/esp32h2-dtls-demo
```

Use `--port /dev/...` with `espflash` when both boards are connected. Boards
connected through their UART-bridge USB port (rather than the native
USB-Serial/JTAG port) flash noticeably faster with `--baud 921600`. The two
feature builds have the same output filename, so flash or copy the server
artifact before building the client. The configured Cargo runner also supports
`cargo run --release --features role-server` and the corresponding client
command.

## Expected sequence

The server should progress through dataset installation, interface startup, and
role changes before listening:

```text
ESP32-H2 Thread DTLS demo: role=server (FTD)
thread: installing canned Active Operational Dataset
thread: FTD configured router-eligible
thread: IPv6 interface up
thread: protocol started
thread: role -> Detached
thread: role -> Leader
thread: required role reached: Leader
server: Leader UDP socket bound on [::]:49191
server: waiting for client (accept attempt 1)
server: DTLS established with [fd24:723:d715:0:...]:49191
server: received: hello 0
```

The client should attach before it attempts DTLS:

```text
ESP32-H2 Thread DTLS demo: role=client (MTD, rx-on)
thread: installing canned Active Operational Dataset
thread: MTD configured rx-on; MTD builds are never router-eligible
thread: IPv6 interface up
thread: protocol started
thread: role -> Detached
thread: role -> Child
thread: required role reached: Child
client: connecting to Leader ALOC [fd24:723:d715::ff:fe00:fc00]:49191 (attempt 1)
client: DTLS established with [fd24:723:d715::ff:fe00:fc00]:49191
client: sending hello 0
client: round trip ok: ack: hello 0
```

Intermediate role transitions and the child's generated address vary. Both
sequences were verified against real two-board ESP32-H2 hardware runs: the
server formed the network and became Leader within seconds, the client
attached as a Child, and sustained `hello`/`ack` round trips ran with no
failures and no panics.

## Troubleshooting

- If the server stays `Detached`, verify it was built with only
  `role-server`, both boards support ESP32-H2 IEEE 802.15.4, and channel 15 is
  usable. Resetting clears this demo's RAM-only OpenThread settings.
- If the client stays `Detached`, wait for the server to reach `Leader`, verify
  the client has the `role-client` image from the same source revision, keep the
  boards close for first bring-up, and check for channel-15 interference.
- If attachment succeeds but DTLS retries, confirm the server remains the only
  router-capable node. The Leader ALOC follows the elected Leader; adding
  another FTD can move it away from the board running the DTLS server.
- Attaching `espflash monitor` (including via `--monitor`) resets the board.
  A freshly flashed board starts running unmonitored, so attaching a monitor
  later reboots it mid-demo: OpenThread settings are RAM-only, the client
  comes back with a new mesh-local address, and the server may report one
  ghost session that established and then timed out. Both retry loops recover
  on their own; to avoid the artifact entirely, attach the monitor immediately
  after flashing.
- A first build needs network access for the pinned Git dependency and
  OpenThread submodule. Subsequent locked builds can use Cargo's cache.
- A failure mentioning missing Clang, CMake, Ninja, or generated bindings
  usually means the OpenThread feature set was changed from the pinned prebuilt
  profile.
- Neither firmware logs the dataset hex, PSKc, Network Key, derived DTLS keys,
  or raw handshake payloads. The OpenThread `log` feature is intentionally
  disabled because its trace-level RAM-settings diagnostics include setting
  values. Do not add blanket radio/protocol tracing around key-bearing packets.
