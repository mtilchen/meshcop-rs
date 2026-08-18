# Feature parity with the C++ `ot-commissioner`

This document tracks MeshCoP for Rust against the OpenThread C++
reference (`github.com/openthread/ot-commissioner`, `include/commissioner`
public API), excluding CCM (Commercial Commissioning Mode) per project scope.
"C++" below refers to that reference implementation.

## Commissioner API matrix

| C++ `Commissioner` API | Rust equivalent | Status |
| --- | --- | --- |
| `Init` / `GetConfig` | `Commissioner::connect(config, addr)` / `config()` | ✅ |
| `Connect` / `Disconnect` | `connect` (DTLS established lazily) / `disconnect` | ✅ |
| `GetSessionId` / `GetState` / `IsActive` | `session_id()` / `state()` | ✅ |
| `IsCcmMode` / `GetDomainName` | CCM excluded; `enable_ccm` is rejected | ✅ (by scope) |
| `Petition` / `Resign` | `petition` / `resign` | ✅ |
| keep-alive (internal timer) | `keep_alive()` (caller-driven) | ✅* see [Async model](#async-model) |
| `GetActiveDataset` / `GetRawActiveDataset` / `SetActiveDataset` | `get_active_dataset` / `get_raw_active_dataset` / `set_active_dataset` (Active Timestamp mandatory, as in C++) | ✅ |
| `GetPendingDataset` / `SetPendingDataset` | `get_pending_dataset` / `set_pending_dataset` (Active/Pending Timestamp and Delay Timer mandatory, as in C++) | ✅ |
| `SetSecurePendingDataset` | `set_secure_pending_dataset` (proxied to the PBBR ALOC, retrieval URI built from the PBBR address; Pending Timestamp and Delay Timer mandatory) | ✅⁺ (CCM-gated in C++; offered here without the gate) |
| `GetCommissionerDataset` / `SetCommissionerDataset` | `get_commissioner_dataset` / `set_commissioner_dataset` (proxied to the leader ALOC; session-ID and border-agent-locator TLVs stripped) | ✅ |
| `GetBbrDataset` / `SetBbrDataset` | `get_bbr_dataset` / `set_bbr_dataset` | ✅⁺ (CCM-gated in C++; offered here without the gate, sent directly to the border agent) |
| `AnnounceBegin` / `PanIdQuery` / `EnergyScan` | `announce_begin` / `pan_id_query` / `energy_scan` (proxied to the destination; multicast → non-confirmable without response wait) | ✅ |
| `RegisterMulticastListener` | `register_multicast_listener` (proxied to the PBBR ALOC) | ✅ |
| `CommandReenroll` / `CommandDomainReset` / `CommandMigrate` | `command_reenroll` / `command_domain_reset` / `command_migrate` (proxied to the destination) | ✅⁺ (CCM-gated in C++; offered here without the gate) |
| `CommandDiagGetQuery` / `CommandDiagReset` | `diagnostic_get` / `diagnostic_reset` (`None` destination → leader ALOC) | ✅ |
| `RequestToken` / `SetToken` | `request_token` / `set_token` return `Error::Unsupported` | ✅ (CCM, deferred by scope) |
| `GeneratePSKc` | `crypto::generate_pskc` | ✅ |
| `ComputeJoinerId` | `crypto::compute_joiner_id` | ✅ |
| `AddJoiner` (steering data) | `crypto::add_joiner_to_steering_data` | ✅ |
| `GetVersion` | `meshcop::version()` | ✅ |
| `CancelRequests` | not needed: requests are `async` and cancelled by dropping futures | ✅ (idiom) |

## CommissionerHandler callbacks

| C++ callback | Rust equivalent |
| --- | --- |
| `OnJoinerRequest` | `JoinerHandler::joiner_pskd` (`None` ignores the joiner; `StaticJoinerHandler` mirrors `CommissionerApp` enablement) |
| `OnJoinerConnected` | `JoinerHandler::on_joiner_connected` + `CommissionerEvent::JoinerConnected` |
| `OnJoinerFinalize` | `JoinerHandler::on_joiner_finalize` + `CommissionerEvent::JoinerFinalized` |
| `OnKeepAliveResponse` | `CommissionerEvent::KeepAliveResponse` |
| `OnPanIdConflict` | `CommissionerEvent::PanIdConflict` |
| `OnEnergyReport` | `CommissionerEvent::EnergyReport` |
| `OnDiagGetAnswerMessage` | `CommissionerEvent::DiagnosticAnswer` (`meshcop::NetDiagData`) |
| `OnDatasetChanged` | `CommissionerEvent::DatasetChanged` (also clears the cached mesh-local prefix, like the C++ proxy) |
| `OnLog` | `MESHCOP_TRACE` stderr tracing |

## Joiner commissioning

The commissioner runs a DTLS 1.2 server (EC J-PAKE over PSKd,
`TLS_ECJPAKE_WITH_AES_128_CCM_8`) for each joiner relayed through
RLY_RX/RLY_TX, with HelloVerifyRequest cookies, answers JOIN_FIN.req on
`/c/jf`, and attaches the Joiner Router KEK
(`SHA-256(key-block)[0..16]`, identical to the mbedTLS export used by both
C++ sides) to the relayed JOIN_FIN.rsp. Sessions expire after the C++
deadline (max handshake time + 20 s) and stale sessions are swept on relay
traffic.

## Intentional divergences from the C++ reference

These are cases where this crate follows the Thread 1.4 specification or
OpenThread's wire behavior instead of the C++ code:

1. **KEK on rejection** — C++ attaches the Joiner Router KEK to rejecting
   JOIN_FIN.rsp messages too. The KEK signals entrustment (§8.4.5.1), so this
   crate attaches it only when the joiner is accepted.
2. **Child Table child ID** — C++ decodes the 9-bit child ID with a
   `<< 9` shift, corrupting IDs ≥ 256. This crate uses the spec layout
   (§10.11.4.4, high bit from the first byte's LSB, `<< 8`).
3. **Connectivity parent priority** — C++ reads the low two bits of the
   first byte; the spec (§4.4.7) and OpenThread place parent priority in the
   two most significant bits.
4. **Mode TLV bits** — C++ maps `0x01`→rx-on-when-idle and `0x04`→network
   data. OpenThread and the spec (§4.4.2) use `0x08` (R), `0x02` (D) and
   `0x01` (N); this crate follows OpenThread.
5. **`send_to_joiner`** — RLY_TX.ntf is non-confirmable and unanswered; this
   crate returns immediately instead of waiting for a response.

## Async model

The C++ library is callback-driven over libevent and re-arms an internal
keep-alive timer. This crate is `async`/await-driven and does not spawn a
background commissioner task: the application awaits `keep_alive()` on the
configured `CommissionerConfig::keepalive_interval`, while unsolicited traffic
is consumed through `Commissioner::next_event()`. Intervals are validated
against the reference's inclusive 30–45 second range. The bundled REPL services
an absolute keep-alive deadline while waiting for input and disconnects after a
failed or non-accepting response; the `netdiag` collector sends proactively
before a diagnostic wait could cross the same deadline. Examples and live tests
resign before exiting, per the working agreement.

## App-layer features (`crates/ot-commissioner-cli`) — out of library scope

The C++ repository also ships an interactive CLI, JSON config/persistence,
security-materials storage, multi-network management, and mDNS border-agent
discovery (`borderagent discover`, `br scan`). Library-level building blocks
for all protocol operations exist here, and
`Commissioner::enable_joiner` / `enable_all_joiners` mirror the
`CommissionerApp` steering-data updates (PSKd provisioning stays with the
`JoinerHandler`). The `commissionerctl` example covers a minimal subset
(connect, petition, dataset read). mDNS discovery would need a small DNS-SD
dependency and is tracked as follow-up work, not part of the protocol parity
target.

## CCM exclusions (per scope)

Token management (`RequestToken`/`SetToken`, `token_manager.cpp`), COM_TOK
signing of MGMT requests, domain handling, and Thread-over-TLS (Ch. 13) are
intentionally not implemented; entry points return `Error::Unsupported`.
