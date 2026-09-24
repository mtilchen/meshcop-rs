# MeshCoP for Rust

[![Quality](https://github.com/mtilchen/meshcop-rs/actions/workflows/quality.yml/badge.svg)](https://github.com/mtilchen/meshcop-rs/actions/workflows/quality.yml)
[![Interop](https://github.com/mtilchen/meshcop-rs/actions/workflows/interop.yml/badge.svg)](https://github.com/mtilchen/meshcop-rs/actions/workflows/interop.yml)
[![Fuzz](https://github.com/mtilchen/meshcop-rs/actions/workflows/fuzz.yml/badge.svg)](https://github.com/mtilchen/meshcop-rs/actions/workflows/fuzz.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust: 1.85+](https://img.shields.io/badge/rustc-1.85%2B-blue.svg)](#minimum-supported-rust-version)
[![Edition 2024](https://img.shields.io/badge/edition-2024-blue.svg)](Cargo.toml)
[![unsafe: none](https://img.shields.io/badge/unsafe-none-brightgreen.svg)](#security-and-quality)

**MeshCoP for Rust is a pure-Rust Thread MeshCoP commissioner.** Commission
Thread devices and manage a network's operational state from Rust — establish
the authenticated DTLS session, petition the border agent, drive management
commands and diagnostics through the mesh, and onboard joiners end to end —
with **no OpenSSL, no mbedTLS, no C toolchain, and zero `unsafe`**.

It implements the non-CCM feature set of the C++
[`ot-commissioner`](https://github.com/openthread/ot-commissioner) reference
(full matrix in [docs/PARITY.md](docs/PARITY.md)), so it is a complete
commissioner rather than a partial reimplementation.

This Cargo workspace contains four crates:

- [`meshcop`](crates/meshcop), the commissioner library.
- [`meshcop-dtls`](crates/meshcop-dtls), the runtime-neutral DTLS 1.2 profile.
- [`ot-commissioner-cli`](crates/ot-commissioner-cli), the faithful CLI port,
  which retains its existing `ot-commissioner-rs` executable name.
- [`meshcop-netdiag`](crates/meshcop-netdiag), the network-diagnostic topology
  mapper.

## Why

- **Pure Rust, zero `unsafe`, no C crypto.** Built on small RustCrypto crates
  instead of OpenSSL or mbedTLS, so it cross-compiles cleanly, keeps the
  dependency and attack surface small, and is memory-safe by construction.
- **Async-native.** A Tokio-facing client API; the underlying protocol state
  machines are runtime-neutral and independently testable.
- **Credential-safe by design.** Library-owned PSKc, network keys, joiner
  PSKds, J-PAKE scalars, datasets, and derived session keys are redacted in
  `Debug` and best-effort zeroized when replaced or dropped. Explicit raw
  access still exposes secret material, and owned encodings become
  caller-managed secret buffers. `unwrap`/`expect` are lint-forbidden in
  production code.
- **Held to a high assurance bar.** Deterministic and gated-live tests, coverage
  gates, mutation testing, fuzzing of every wire parser, and supply-chain
  checks — all CI-enforced (see [below](#security-and-quality)).

## What it does

- Establishes the Thread DTLS 1.2 session authenticated with **EC J-PAKE over
  PSKc**, petitions a border agent, and keeps the session alive.
- Reads and writes **active, pending, secure-pending, commissioner, and BBR
  datasets** through a TLV codec that preserves wire order, duplicates, and
  unknown TLVs.
- Routes management commands the way the reference does — commissioner-dataset
  operations, multicast-listener registration, secure pending dissemination,
  **announce / PAN-ID / energy scans**, and **network diagnostics** — through
  the UDP_TX/UDP_RX border-agent proxy with mesh-local ALOC addressing;
  diagnostic answers decode into a typed `NetDiagData` model.
- Commissions **joiners end to end** over the RLY_RX/RLY_TX relay: runs the DTLS
  server side of EC J-PAKE over the joiner PSKd (with HelloVerifyRequest
  cookies), answers JOIN_FIN, and entrusts accepted joiners with the Joiner
  Router KEK.

## Example

```rust
use std::{net::SocketAddr, time::Duration};

use meshcop::{
    commissioner::{
        Commissioner, CommissionerConfig, CommissionerEvent, DatasetFlags, StaticJoinerHandler,
    },
    dataset::Dataset,
};

#[tokio::main(flavor = "local")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The commissioner authenticates with a PSKc. Derive it from an operational
    // dataset (the usual case — dataset hex is what Thread tooling hands you):
    let dataset = Dataset::from_hex(std::env::var("THREAD_DATASET_HEX")?)?;
    let config = CommissionerConfig::from_dataset("my-commissioner", &dataset)?;
    // ...or pass a Pskc (or a raw 16-byte array) straight in:
    //   let config = CommissionerConfig::pskc("my-commissioner", pskc_bytes);
    let border_agent: SocketAddr = std::env::var("MESHCOP_BORDER_AGENT")?.parse()?;

    // One call: DTLS handshake (EC J-PAKE over the PSKc), petition, and a
    // background task that keeps the session alive from here on.
    let (commissioner, mut events) = Commissioner::connect(config, border_agent).await?;

    // Let joiners in: the handler answers their DTLS handshakes with this PSKd,
    // and opening the steering data tells the network to accept them.
    let mut joiners = StaticJoinerHandler::new();
    joiners.enable_all("J01NME");
    commissioner.set_joiner_handler(joiners)?;
    commissioner.enable_all_joiners(true).await?;

    // The handle is a cheap clone, usable from any task.
    let monitor = commissioner.clone();
    tokio::spawn(async move {
        let mut every_minute = tokio::time::interval(Duration::from_secs(60));
        loop {
            every_minute.tick().await;
            match monitor.get_active_dataset(DatasetFlags::ALL).await {
                Ok(active) => println!("network: {:?}", active.network_name()),
                Err(error) => break eprintln!("monitor stopped: {error}"),
            }
        }
    });

    // No keep-alive bookkeeping: just react to what the network tells us.
    while let Some(event) = events.next().await {
        match event {
            CommissionerEvent::JoinerFinalized {
                joiner_id,
                accepted: true,
                info,
                ..
            } => {
                println!(
                    "joined: {joiner_id:02x?} ({} {})",
                    info.vendor_name, info.vendor_model
                );
                break;
            }
            CommissionerEvent::SessionLost { reason } => {
                return Err(format!("session lost: {reason}").into());
            }
            _ => {}
        }
    }

    // Close the network to joiners again, then resign cleanly.
    commissioner.enable_all_joiners(false).await?;
    commissioner.resign().await?;
    Ok(())
}
```

### Sessions

`Commissioner::connect` returns a cheap, cloneable handle and an `Events`
stream. A background task started on the current Tokio runtime (any flavor,
including `LocalRuntime`) runs the session:

- It **sends keep-alives** every `keepalive_interval` while the petition is
  active. Set `KeepAlive::Manual` to send them yourself with `keep_alive()`.
- It **matches responses to requests**, retransmits lost confirmable requests,
  and lets handle clones in different tasks issue requests concurrently. They
  are sent one at a time; keep-alives never wait behind them.
- It **publishes events** (scan reports, diagnostics answers, joiner progress,
  keep-alive results, and `SessionLost`) to every `Events` subscriber. A
  subscriber that falls more than `event_capacity` events behind receives
  `Lagged` instead of slowing the session down.
- It **commissions joiners** through a `JoinerHandler` installed with
  `set_joiner_handler`.

`Commissioner::connect_only` opens the DTLS session without petitioning, which
is enough to read datasets; call `petition()` later to take the commissioner
role. An OpenThread border agent closes an unpetitioned session about 50
seconds after the handshake; the session then reopens on the next request.
The same agent silently drops proxied (UDP_TX) traffic, such as network
diagnostics, until the petition is accepted.

A session ends when you call `resign()`, when the border agent rejects a
keep-alive or closes the session, or when every handle is dropped. Requests
still outstanding then fail with `Error::SessionLost`. Call `resign()` before
your program exits: a runtime that is shutting down cancels the background
task before it can resign on its own.

The `meshcop-netdiag` crate provides a network-diagnostic topology mapper; run
it with `cargo run -p meshcop-netdiag -- --help`. The
[`examples/`](crates/meshcop/examples) directory also has read-only
live probes and a small `commissionerctl`. These tools redact dataset secrets
by default and resign read-only sessions before exiting; mutating operations
are gated behind `MESHCOP_MUTATE_OK=1` so routine inspection cannot
disturb a live network.

## Security and Quality

This crate handles sensitive Thread credentials — PSKc, joiner PSKds, network
keys, and full operational datasets — and is built and tested accordingly. See
[SECURITY.md](SECURITY.md) for the threat model and the vulnerability-disclosure
process.

- **Pure Rust, no `unsafe`.** `#![forbid(unsafe_code)]`; built on small
  RustCrypto crates with no OpenSSL or mbedTLS runtime dependency.
- **Secret hygiene.** Library-owned PSKc, joiner PSKds, J-PAKE scalars,
  datasets, and record-protection keys are redacted in `Debug` and best-effort
  zeroized when replaced or dropped. `Dataset::raw` and `Dataset::entries`
  deliberately expose borrowed secret views; `to_bytes`, `to_hex`, and typed
  accessors that copy secret fields create caller-managed values. Constant-time
  primitives (`subtle` / RustCrypto) are used where applicable.
- **Tests.** The deterministic suite includes in-memory DTLS
  client-against-server handshakes, an in-process loopback DTLS server
  exercising the Tokio session driver, and a complete fake-joiner
  commissioning flow, plus gated live border-router tests. Testing policy: no
  public commissioner operation lands without a scripted API test, no wire
  parser lands without malformed-input coverage, and crypto/protocol state
  machines carry negative-path tests, not only happy-path vectors.
- **Live interop (CI-enforced).** Every change commissions a real OpenThread
  border agent (posix `ot-daemon` at a pinned release, driven by a simulated
  RCP) via [interop.yml](.github/workflows/interop.yml): successful and
  wrong-credential DTLS authentication, commissioner petition/arbitration and
  takeover, protocol-aware loss injection at every DTLS handshake flight
  position and for the first CoAP petition request/response, keep-alive,
  dataset reads, synchronous and asynchronous network diagnostics, and a
  complete joiner commissioning of a simulated OpenThread node through
  JOIN_FIN, KEK entrustment, and attachment.
  A weekly scheduled run catches drift even when this repo is quiet. The full
  interoperability matrix — and what is verified continuously versus by hand —
  is in [docs/INTEROP.md](docs/INTEROP.md).
- **Coverage gates (CI-enforced).** Minimum 80% line, 80% region, and 75%
  function coverage via `cargo-llvm-cov`.
- **Mutation testing.** `cargo-mutants` runs against the high-risk protocol
  files (EC J-PAKE, DTLS drivers and handshakes, CoAP, diagnostic and
  notification parsers, the commissioner client, and joiner sessions).
  Intentional exclusions are limited to equivalent transformations,
  intrinsically unobservable behavior, and uncontracted diagnostic output;
  each exclusion is documented rather than left silent.
- **Fuzzing.** 13 coverage-guided libFuzzer targets cover every wire parser
  (TLV, dataset, CoAP, DTLS record/handshake/hello, EC J-PAKE key-exchange and
  KKPP, UDP_RX decapsulation, network-diagnostic data, JOIN_FIN), run weekly
  and on demand via [fuzz.yml](.github/workflows/fuzz.yml).
- **Supply chain.** `cargo audit --deny warnings` (advisories) and `cargo deny
  check` (licenses, bans, sources) gate the dependency graph.
- **Reference parity.** Crypto and handshake paths are validated against known
  Thread specification vectors and the OpenThread `ot-commissioner` / mbedTLS
  reference implementations.

Reproduce the core gate locally:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## CI Quality Reports

GitHub Actions drives the full quality process from
[quality.yml](.github/workflows/quality.yml):

- `verify` runs `cargo fmt --all --check`, clippy with `-D warnings` across the
  workspace, and `cargo test --workspace --all-features`.
- `coverage` runs [tools/ci/coverage.sh](tools/ci/coverage.sh), enforces the
  current coverage thresholds, writes a GitHub job summary, and uploads
  `coverage-summary.json`, `lcov.info`, and the HTML report as artifacts.
- `mutants` runs [tools/ci/mutants.sh](tools/ci/mutants.sh), writes a GitHub job
  summary, and uploads `mutants.out` as an artifact.

Mutation testing defaults to the `targeted` scope for the high-risk protocol
files. A manual workflow dispatch can choose `full`, `custom`, or `skip`.
For `custom`, set the repository or organization variable
`CARGO_MUTANTS_FILES` to a space-separated list of file globs.

Generated coverage and mutation reports are CI artifacts, not source files, so
they should not be committed to the repository.

## Limitations and non-goals

In the interest of accuracy (see [SECURITY.md](SECURITY.md) for the full threat
model):

- **Not yet independently audited.** The cryptographic and protocol code has not
  had a third-party security audit. Treat it accordingly until that changes.
- **CCM (token/certificate) commissioning is not implemented** and returns
  `Error::Unsupported`. The supported authentication path is EC J-PAKE over
  PSKc.
- **Documented mutation exclusions.** Remaining exclusions are limited to
  equivalent transformations, behavior that is intrinsically unobservable in
  safe Rust, and intentionally uncontracted diagnostic output. Each is
  catalogued in [docs/MUTATION_SURVIVORS.md](docs/MUTATION_SURVIVORS.md).
- **Side-channel scope.** Constant-time primitives are used, but the crate is
  not hardened against power, EM, or microarchitectural side channels.
- **Pre-1.0 API.** Public APIs may change before 1.0.

## Minimum supported Rust version

This crate requires Rust **1.85** or newer (edition 2024) and builds on stable.
Nightly is confined to the isolated `fuzz/` crate.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

## Disclaimer

This is an independent, personal open-source project. It is not endorsed by,
affiliated with, or sponsored by the Thread Group, Google, Google Nest, or the
author's employer. THREAD, OPENTHREAD, and related marks belong to their
respective owners. They are used here only to identify the protocols this
project implements and the software with which it interoperates.
