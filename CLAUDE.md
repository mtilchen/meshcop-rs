# CLAUDE.md

The canonical working agreement for this repo lives in `AGENTS.md` (environment
variables, Rust conventions, coverage/mutation expectations, live-test gating,
tooling preferences). Read it and treat it as authoritative.

@AGENTS.md

The notes below are an orientation map; they do not override `AGENTS.md`.

## What this crate is

Mesh Five-O (`mesh50`) is a pure-Rust Thread MeshCoP commissioner with the
non-CCM feature set of the C++ `ot-commissioner` reference (matrix in
`docs/PARITY.md`). It establishes a Thread DTLS 1.2 session authenticated with
EC J-PAKE over PSKc, petitions a border agent, keeps the session alive,
reads/writes operational and commissioner datasets, routes MGMT commands and
network diagnostics through the UDP_TX/UDP_RX proxy (ALOC addressing), and
commissions joiners over the relay (DTLS server over PSKd, JOIN_FIN, KEK
entrustment). Crypto is built on small RustCrypto crates — no OpenSSL or
mbedTLS at runtime.

## Reference specifications

- Thread 1.4.0 specification — the wire formats, MeshCoP CoAP resources, dataset
  TLVs, and security policy bits implemented here.
- RFC 8236 (J-PAKE) and RFC 8235 (Schnorr NIZK) — the EC J-PAKE handshake in
  `crates/mesh50-dtls/src/ecjpake/` follows the EC form of both.
- OpenThread `ot-commissioner` (github.com/openthread/ot-commissioner) — the C++
  reference implementation, used for parity and as a source of test vectors. The
  `tools/mbedtls_*.c` harnesses and the mbedTLS reference vector in the
  `ecjpake` tests come from this lineage.

## Workspace map (`crates/`)

Four Cargo-workspace members (root `Cargo.toml`), plus `fuzz/` and
`demo/esp32h2-dtls/`, which are excluded workspaces with their own lockfiles.
The demo is two-role ESP32-H2 firmware for commissioner-style DTLS over a real
two-node OpenThread IPv6 network.

- `crates/mesh50-dtls` — Mesh Five-O's Thread MeshCoP DTLS 1.2 profile,
  standalone with `no_std` + `alloc` support and runtime-neutral apart from its
  optional Tokio session driver.
  - `ecjpake/` — EC J-PAKE party + Schnorr NIZK over P-256, split into the
    protocol state machine and shared P-256 helpers (`mod.rs`), the Schnorr
    proof gen/verify (`schnorr.rs`), and the TLS `ECJPAKEKeyKPPairList` /
    key-exchange codecs (`codec.rs`).
  - `ccm.rs` — AES-CCM-8 record protection: `RecordProtectionKey` and
    `AesCcm8`.
  - `thread_handshake.rs` is the runtime-neutral client handshake state
    machine and `thread_server_handshake.rs` its server counterpart (used for
    joiner sessions; includes HelloVerifyRequest cookies and Joiner Router KEK
    export); `driver.rs`, `client_driver.rs`, and `server_driver.rs` provide
    runtime-generic client+server async drivers, with `tokio_session.rs`
    preserving the `DtlsSession::connect` convenience API. Record framing
    (`record.rs`), the TLS 1.2 PRF key schedule (`key_schedule.rs`), and
    AES-128-CCM-8 record protection (`record_protection.rs`) live in sibling
    files.
  - `error.rs` — this crate's own `thiserror` `Error`/`Result`.
  - `test_support.rs` — in-process loopback DTLS server for deterministic
    handshake tests, gated behind the `test-support` feature. Unit tests live
    in `tests/`.
- `crates/mesh50` — the Mesh Five-O library.
  - `tlv.rs` — Thread TLV codec. Preserves wire order, duplicates, unknown
    types, and supports the extended (0xff) length form. Foundation for
    everything else.
  - `dataset.rs` — Operational dataset (`Dataset` = active/pending alias)
    built on `TlvSet`, with typed accessors (channel, PAN ID, security policy,
    timestamps, channel mask, …) that validate lengths.
  - `crypto/` — now just `pskc.rs` (the redacted, zeroizing `Pskc` credential
    type, PSKc derivation via PBKDF2-AES-CMAC-PRF-128, joiner ID, and
    steering-data Bloom filter).
  - `meshcop/` — CoAP codec (`coap.rs`), MeshCoP request builders
    (`builders.rs`, incl. UDP_TX/RLY_TX encapsulation), response/notification
    parsers (`parsers.rs`, incl. UDP_RX decapsulation), URI + TLV constants,
    and the dataset-flag → TLV-type mapping (`flags.rs`). The
    network-diagnostic data model lives in `diag/` (`model.rs` types,
    `decode.rs` wire decoders, `diag_flags.rs` request flags, `NetDiagData`).
  - `commissioner/` — Async public API. `client/` holds `Commissioner`, split
    by concern: `mod.rs` (struct, connect, lifecycle, shared helpers),
    `datasets.rs` (operational/commissioner/BBR dataset get/set),
    `commands.rs` (announce/scan/PAN-ID and managed-device commands),
    `diagnostics.rs` (network-diagnostic queries), `relay.rs` (joiner relay
    handling), and `transport.rs` (DTLS session, request/response routing,
    mesh-local-prefix/ALOC routing, UDP-proxy encapsulation). `joiner.rs`
    holds the joiner session state machine plus `JoinerHandler` /
    `StaticJoinerHandler`. `harness.rs` is a test-only scripted MeshCoP
    transport that exercises the production incoming-message loop, `pub`
    behind the `test-support` feature.
  - `error.rs` — Crate-wide `thiserror` `Error`/`Result`, including a
    transparent `Dtls` variant wrapping `mesh50_dtls::Error`.
  - `tests/` (`interop_openthread.rs`, `live_border_router.rs`) and
    `examples/` live here too.
- `crates/ot-commissioner-cli` — the example REPL port (still named
  `ot-commissioner-rs`), formerly the library's `cli` feature. Run it with
  `cargo run -p ot-commissioner-cli`. Its scripted tests use the library's
  `test-support` feature.
- `crates/mesh50-netdiag` — Mesh Five-O's read-only Thread network topology and
  diagnostics collector. Run it with
  `cargo run -p mesh50-netdiag -- --help`.

## Conventions and gotchas worth knowing

- Library-owned secrets (PSKc, PSKd, J-PAKE scalars, datasets, and derived
  keys) are redacted in `Debug` and best-effort zeroized when replaced or
  dropped. Explicit raw access exposes secrets, and owned exports are
  caller-managed. Examples redact dataset fields unless `--show-secrets` is
  passed.
- Keep-alives are application-driven: schedule `Commissioner::keep_alive()`
  using `CommissionerConfig::keepalive_interval`. The bundled REPL and
  `netdiag` collector do this while their sessions are active.
- Live border-router tests are `#[ignore]` and require a real agent plus
  `ESP_MATTER_TEST_THREAD_DATASET_HEX`; they must not leak secrets.
- Mutating CLI/example operations are gated behind `MESH50_MUTATE_OK=1`.
- CCM (token/certificate) flows are intentionally deferred and return
  `Error::Unsupported`.
- `MESH50_TRACE` prints non-secret MeshCoP and DTLS protocol traces to
  stderr as `[meshcop] message` and `[dtls] message`.
- `MESH50_TRACE_SECRETS` additionally prints sensitive DTLS key
  material and plaintext to stderr as `[dtls-secret] message`. Use it only in
  controlled debugging environments.

## Verify (must pass before work is "done", per AGENTS.md)

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

When touching `crates/mesh50-dtls`, also build the no_std profile the CI
`no-std` job enforces — host gates always have `std` on and cannot catch
`std`/`eprintln!` leaking into un-gated code:

```sh
cargo build -p mesh50-dtls --no-default-features --target riscv32imac-unknown-none-elf
```

When adding, deleting, or demoting source files in a crate the mutation gate
targets, check that the `targeted` globs in `tools/ci/mutants.sh` still
describe the production surface — the gate silently keeps mutating whatever
the globs name, including retired code, while new files escape it.

`tools/ci/coverage.sh` (cargo-llvm-cov) and `tools/ci/mutants.sh`
(cargo-mutants) back the coverage and mutation gates in
`.github/workflows/quality.yml`.

## Supply chain

`cargo audit --deny warnings` (advisories) and `cargo deny check` (licenses,
bans, sources; config in `deny.toml`) gate the dependency graph in the
`supply-chain` job of `.github/workflows/quality.yml`.

## Fuzzing

Coverage-guided fuzz harnesses for every wire parser live in the isolated
`fuzz/` crate (libfuzzer). It is excluded from the stable workspace and requires
nightly, so it never gates normal PRs:

```sh
cargo +nightly fuzz run <target> -- -max_total_time=60   # e.g. dtls_record
cargo +nightly fuzz list                                 # all targets
```

`.github/workflows/fuzz.yml` runs every target weekly and on demand.
