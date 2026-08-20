# Interoperability

What MeshCoP for Rust has been verified to interoperate with, and — just as
importantly — at what level of assurance. The rows are deliberately separated by
**how** each was verified, because "passes on every CI run" and "the author ran
it once against a device on the bench" are very different claims:

- **Continuous** — runs automatically on every change in CI; reproducible by
  anyone from this repo. The strongest claim.
- **Manual** — gated `#[ignore]` tests the author runs by hand against physical
  hardware. Point-in-time, not continuously re-verified, hardware-specific.
- **Vector** — primitive-level golden vectors whose expected values come from an
  independent implementation. Cross-implementation conformance, not device
  interop; runs on every build. Catalogued in [VECTORS.md](VECTORS.md).

## Matrix

| Peer | Roles exercised | Assurance | Where |
| --- | --- | --- | --- |
| **OpenThread** `v2026.06.0` — posix `ot-daemon` (border agent + leader) + simulated RCP | Commissioner authentication, loss recovery, arbitration, diagnostics, and joiner commissioning | Continuous (every PR/push + weekly) | [interop.yml](../.github/workflows/interop.yml), [tools/ci/interop.sh](../tools/ci/interop.sh) |
| **Physical Thread border router** (Espressif ESP-Matter) | Commissioner session + dataset/commissioner-dataset reads | Manual, author-run, point-in-time | [tests/live_border_router.rs](../crates/meshcop/tests/live_border_router.rs) |
| **mbedTLS / OpenSSL / Thread spec / OpenThread** | Crypto primitives + key schedule | Vector (every build) | [VECTORS.md](VECTORS.md) |

## OpenThread — continuous, full role coverage

The [interop gate](../.github/workflows/interop.yml) builds OpenThread at a
pinned release (a posix `ot-daemon` border router driven by a simulated RCP over
forkpty — the arrangement the C++ `ot-commissioner` integration suite uses),
forms a Thread network, and runs six gated tests against the live border agent
on loopback:

- **Commissioner session:** DTLS 1.2 + EC J-PAKE handshake (PSKc), `COMM_PET`
  petition, `COMM_KA` keep-alive, `MGMT_ACTIVE_GET` with a full, order-insensitive
  active-dataset comparison against the leader's own view, `MGMT_COMMISSIONER_GET`
  routed through the UDP_TX/UDP_RX proxy to the leader ALOC, and a clean resign.
- **Authentication failure and recovery:** a commissioner using the wrong PSKc
  must fail during DTLS authentication, after which a fresh commissioner using
  the correct PSKc must immediately petition and resign successfully.
- **Packet-loss recovery:** a protocol-aware loopback UDP fault proxy recognizes
  handshake messages rather than assuming fixed packet ordinals. In separate
  sessions it drops one datagram from each of the three commissioner and three
  border-agent flight positions, then the first CoAP petition request and
  response. Every case must still petition and resign against OpenThread.
- **Commissioner arbitration:** while one commissioner is active, a second
  commissioner must receive a petition rejection naming the incumbent. After
  the incumbent resigns, that same contender must petition successfully.
- **Network diagnostics:** both unicast `DIAG_GET.req` and asynchronous
  `DIAG_GET.qry`/`DIAG_GET.ans` exchanges are proxied to the OpenThread leader;
  their MAC Address, Mode, Route64, and Leader Data TLVs are decoded and
  required.
- **Joiner commissioning:** advertise a specific joiner by EUI-64 in the steering
  data (exercising the SHA-256 joiner-ID derivation and Bloom filter against
  OpenThread's own computation), then drive a real simulated `ot-cli-ftd` node
  through the joiner DTLS session over `RLY_RX`/`RLY_TX` (PSKd), `JOIN_FIN`, the
  KEK hand-off to the joiner router, and finally watch it attach to the network.
  The harness explicitly sets `MESHCOP_MUTATE_OK=1` for this disposable network.

A weekly scheduled run catches drift against OpenThread even when this repo is
quiet. Reproduce locally on Linux with `tools/ci/interop.sh`. The pinned
OpenThread ref lives in [`tools/ci/openthread-ref`](../tools/ci/openthread-ref)
and may be overridden with `MESHCOP_INTEROP_OPENTHREAD_REF`; cached binaries are
reused only after their checked-out commit is verified against the effective
ref.

## Physical border router — manual, read-only

[`tests/live_border_router.rs`](../crates/meshcop/tests/live_border_router.rs) holds `#[ignore]` tests that run against a real
Thread border agent (an Espressif ESP-Matter border router on the author's
bench), selected via `MESHCOP_BORDER_AGENT` with the network dataset in
`ESP_MATTER_TEST_THREAD_DATASET_HEX`. They have been run by hand and exercise the
full DTLS + EC J-PAKE handshake, petition, keep-alive, active-dataset read and
comparison, commissioner-dataset read, border-agent locator, and clean resign.

Scope and caveats:

- This is **point-in-time** validation against specific firmware, not a
  continuously re-verified claim. It is not run in CI (it needs physical
  hardware and real credentials).
- Coverage here is **read-only / inspection**. Mutating operations
  (`*dataset set`, joiner commissioning, MLR, announce, PAN-ID query, energy
  scan) are **not** part of the verified physical-hardware path yet — joiner
  commissioning end to end is covered against OpenThread (above), not against
  this hardware.
- The tests never print PSKc, network keys, or dataset values; mutating live
  operations are additionally gated behind `MESHCOP_MUTATE_OK=1`.

## Cross-implementation vectors — every build

Primitive-level conformance against independent implementations: PSKc (Thread
spec), TLS 1.2 PRF and Finished `verify_data` and the key schedule and
AES-128-CCM-8 record protection (OpenSSL), the EC J-PAKE premaster secret
(mbedTLS), and joiner-ID derivation (OpenThread). These run on every build and
are catalogued — with provenance and regeneration commands — in
[VECTORS.md](VECTORS.md).

## Gaps

- **Joiner commissioning against physical hardware** — covered against
  OpenThread, not yet against a bench border router.
- **Mutating operations against physical hardware** — see the read-only caveat
  above.
- **Additional stacks** — only OpenThread is covered continuously. Other
  certified Thread stacks (other silicon vendors, other border-router firmware)
  are untested; contributions adding rows here are welcome.
