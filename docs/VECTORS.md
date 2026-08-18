# Cross-implementation test vectors

This crate's cryptographic and key-schedule code is pinned to **golden vectors**
whose expected values were produced by an *independent* implementation — the
Thread specification, OpenSSL, or mbedTLS — rather than by this crate. A golden
vector fails if our output drifts from the reference, so it proves
interoperability, not merely internal consistency.

Each entry below records what the vector proves, where the expected value came
from, the exact inputs, and a command that regenerates it from the reference.
Round-trip and property tests (encrypt-then-decrypt, encode-then-decode) live
next to the code they exercise and are intentionally *not* listed here: they
prove self-consistency, which is a weaker claim.

The live [interop gate](../.github/workflows/interop.yml) is the system-level
counterpart to this primitive-level catalog: it commissions a real OpenThread
border agent (and a simulated joiner) on every change.

> Regeneration uses OpenSSL 3.x (`openssl kdf … TLS1-PRF`), Python
> [`cryptography`](https://cryptography.io) (`AESCCM`), and the mbedTLS
> harnesses under [`tools/`](../tools). None are runtime dependencies.

---

## PSKc — PBKDF2-AES-CMAC-PRF-128

- **Proves:** PSKc derivation matches the Thread specification's own worked
  example.
- **Source:** Thread 1.4.0 Specification **§8.4.1.2.1 "Derivation of PSKc"**,
  the *Test Vector for Derivation of PSKc* (PDF p. 337). The vector is carried
  unchanged from Thread 1.2 and is also exercised by OpenThread's commissioner
  tests.
- **Inputs:** passphrase `12SECRETPASSWORD34`, network name `Test Network`,
  extended PAN ID `0001020304050607`.
- **Expected:** `c3f59368445a1b6106be420a706d4cc9`.
- **Regenerate:** the value is a published spec constant (PBKDF2 over
  AES-CMAC-PRF-128, 16384 iterations). Independently reproduced by OpenThread's
  `Commissioner` test suite; there is no one-line CLI equivalent.
- **Test:** `crates/meshcop/src/crypto/pskc.rs` → `generates_thread_pskc_test_vector`.

---

## TLS 1.2 PRF — P_SHA-256 (RFC 5246 §5)

- **Proves:** the TLS 1.2 pseudo-random function (the basis of every key in the
  DTLS profile) matches OpenSSL byte-for-byte.
- **Source:** OpenSSL `TLS1-PRF` KDF.
- **Inputs:** secret `0102030405060708090a0b0c0d0e0f10`, label `label`, seed
  `1112131415161718191a1b1c1d1e1f20`, 64 output bytes.
- **Expected:**
  `6f1e214164ea8f30cad635312e2af08967331da73926cecfc0f1307884aa7929` +
  `74c5cc463d3293d5fad2a9dab2f58d6f667de184d266b32150fc21a0c464326d`.
- **Regenerate:**
  ```sh
  openssl kdf -keylen 64 -binary -kdfopt digest:SHA2-256 \
    -kdfopt hexsecret:0102030405060708090a0b0c0d0e0f10 \
    -kdfopt seed:label \
    -kdfopt hexseed:1112131415161718191a1b1c1d1e1f20 TLS1-PRF | xxd -p -c64
  ```
- **Test:** `crates/meshcop-dtls/src/tests/keys.rs` → `tls12_prf_matches_openssl_tls1_prf_vector`.

---

## Finished verify_data — PRF over the handshake transcript (RFC 5246 §7.4.9)

- **Proves:** the Finished `verify_data` computation — PRF keyed by the master
  secret over `SHA-256(transcript)` with the `client finished` label — matches
  OpenSSL, using this crate's DTLS handshake-message framing for the transcript.
- **Source:** OpenSSL `TLS1-PRF` over a transcript hash this crate produces.
- **Inputs:** transcript = one ClientHello with payload `abc`; master secret =
  48 bytes of `0x11`; role = client (`client finished`); 12 output bytes. The
  transcript bytes are the DTLS handshake message
  `010000030000000000000003616263` (1-byte type `01`, 3-byte length, 2-byte
  message_seq, 3-byte fragment offset, 3-byte fragment length, then `abc`).
- **Expected:** `6e0903525cefac795bc86d2e`.
- **Regenerate:**
  ```sh
  th=$(printf '010000030000000000000003616263' | xxd -r -p \
       | openssl dgst -sha256 -binary | xxd -p -c32)
  openssl kdf -keylen 12 -binary -kdfopt digest:SHA2-256 \
    -kdfopt hexsecret:$(printf '11%.0s' {1..48}) \
    -kdfopt seed:'client finished' -kdfopt hexseed:$th TLS1-PRF | xxd -p -c12
  ```
- **Test:** `crates/meshcop-dtls/src/tests/keys.rs` → `finished_verify_data_matches_openssl_tls1_prf_vector`.

---

## EC J-PAKE handshake — premaster secret (RFC 8236 / RFC 8235)

- **Proves:** our EC J-PAKE round-two point computation and premaster-secret
  derivation match mbedTLS — the canonical EC-JPAKE-for-TLS implementation —
  given identical scalars and round messages.
- **Source:** mbedTLS, via the harnesses
  [`tools/mbedtls_ecjpake_verify_round_two.c`](../tools/mbedtls_ecjpake_verify_round_two.c)
  and [`tools/mbedtls_ecjpake_dtls_server.c`](../tools/mbedtls_ecjpake_dtls_server.c).
  This is a **cross-implementation conformance vector**, not a verbatim entry
  from mbedTLS's published test suite: the scalars are fixed deterministic
  inputs fed to both implementations, and the round-one/round-two messages and
  expected premaster secret are what mbedTLS produces for them.
- **Inputs:** PSKd `threadjpaketest`; client scalars
  `0102…1e1f21` / `6162…7e7f81`; server scalars `6162…7e7f81` /
  `c1c2…dedfe1` (full values in the test); round-one and round-two messages as
  listed in the test.
- **Expected premaster secret:**
  `f3d47f599844db92a569bbe7981e39d931fd743bf22e98f9b438f719d3c4f351`.
- **Regenerate:** feed the client/server round messages to
  `tools/mbedtls_ecjpake_verify_round_two.c` (built against mbedTLS); it parses
  and validates the round-two messages and derives the premaster secret.
- **Test:** `crates/meshcop-dtls/src/ecjpake/tests.rs` →
  `mbedtls_reference_handshake_derives_expected_premaster_secret`.

---

## Key schedule — master secret, key block, joiner-router KEK

- **Proves:** the full DTLS key-schedule chain (master secret → AES-128-CCM-8
  key block → joiner-router KEK) matches OpenSSL/SHA-256, seeded by the mbedTLS
  EC J-PAKE premaster secret above so the two vectors compose into one chain.
- **Source:** OpenSSL `TLS1-PRF` (master secret, key block) and SHA-256 (KEK).
- **Inputs:** premaster secret = the EC J-PAKE result
  `f3d47f59…d3c4f351`; client_random
  `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`;
  server_random
  `202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f`.
  **Seed order differs by step:** master secret uses `client_random ||
  server_random`; the key block uses `server_random || client_random`.
- **Expected:**
  - master secret
    `e5a288cfe36f82c04a92a820e8e0c768e1d48b9740c8d018f14d9a2b1f7f3e333` +
    `30b1a741f2daf5d156144d8170befaa8`
  - client_write_key `710b83fb8d70267ead91effdd7eb79fe`,
    server_write_key `bec55f8c6af131a377e62e471ca5a38c`,
    client_write_iv `da24a9d2`, server_write_iv `95369b74`
  - joiner-router KEK `adf385fd8aa5cdbd6fe31939ce81d773`
    (`SHA-256(key_block)[..16]`).
- **Regenerate:**
  ```sh
  pms=f3d47f599844db92a569bbe7981e39d931fd743bf22e98f9b438f719d3c4f351
  cr=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  sr=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
  ms=$(openssl kdf -keylen 48 -binary -kdfopt digest:SHA2-256 \
       -kdfopt hexsecret:$pms -kdfopt seed:'master secret' \
       -kdfopt hexseed:$cr$sr TLS1-PRF | xxd -p -c96)
  kb=$(openssl kdf -keylen 40 -binary -kdfopt digest:SHA2-256 \
       -kdfopt hexsecret:$ms -kdfopt seed:'key expansion' \
       -kdfopt hexseed:$sr$cr TLS1-PRF | xxd -p -c80)
  printf '%s' "$kb" | xxd -r -p | openssl dgst -sha256 -binary | xxd -p -c32 | cut -c1-32  # KEK
  ```
- **Test:** `crates/meshcop-dtls/src/tests/keys.rs` →
  `key_schedule_chain_matches_openssl_tls1_prf_vectors`.

---

## Joiner ID — SHA-256 of the EUI-64

- **Proves:** joiner ID derivation (`SHA-256(EUI-64)[..8]` with the
  local/external address bit set) matches OpenThread, so steering data this
  crate builds advertises the same joiner an OpenThread node computes for
  itself.
- **Source:** OpenThread simulation node `ot-cli-ftd 2`, factory EUI-64
  `18b4300000000002`, via its `joiner id` CLI command.
- **Inputs:** EUI-64 `18b4300000000002`.
- **Expected:** `d65e64fa83f81cf7`.
- **Regenerate:**
  ```sh
  printf 'joiner id\n' | ot-cli-ftd 2   # prints d65e64fa83f81cf7
  # or, from the EUI-64 directly:
  python3 -c 'import hashlib; d=hashlib.sha256(bytes.fromhex("18b4300000000002")).digest()[:8]; print((bytes([d[0]|2])+d[1:]).hex())'
  ```
- **Test:** `crates/meshcop/src/crypto/pskc.rs` → `compute_joiner_id_matches_openthread`.

---

## Steering data — CRC-16 Bloom filter (Thread §8.4.4.3)

- **Proves:** the steering-data Bloom filter matches the Thread specification's
  algorithm, so a joiner this crate advertises is the one a real Thread device
  computes for itself. (The end-to-end counterpart — a real OpenThread joiner
  discovering itself in our steering data and attaching — is the joiner leg of
  the [interop gate](../.github/workflows/interop.yml).)
- **Source:** Thread 1.4.0 Specification **§8.4.4.3 "Bloom Filters"**. The spec
  defines the algorithm (k = 2; hash1 = CRC16-CCITT `0x1021`, hash2 =
  CRC16-ANSI `0x8005`; `bloom_filter |= 1 << (hashfn(id) % m)`; `m` = 128;
  big-endian bit mask) but provides **no worked numeric example**, so the
  expected bytes are derived independently from that algorithm. The two CRC
  polynomials are independently anchored by their published catalog check
  values (CRC-16/XMODEM `0x31c3`, CRC-16/BUYPASS `0xfee8` over `123456789`),
  asserted in `crc16_matches_known_catalog_check_values`.
- **Inputs / expected:**
  - joiner ID `d65e64fa83f81cf7` (the OpenThread joiner above): CRC16-CCITT
    % 128 = 1, CRC16-ANSI % 128 = 4 → bits 1 and 4 of the final byte →
    `00000000000000000000000000000012`.
  - bytes `0102030405060708`: bit 44, bit 14 →
    `00000000000000000000100000004000`.
- **Regenerate:**
  ```python
  def crc16(poly, data):
      crc = 0
      for b in data:
          crc ^= b << 8
          for _ in range(8):
              crc = ((crc << 1) ^ poly) & 0xffff if crc & 0x8000 else (crc << 1) & 0xffff
      return crc
  def steering(jid, length=16):
      m, out = length * 8, bytearray(length)
      for poly in (0x1021, 0x8005):           # CCITT, ANSI
          bit = crc16(poly, jid) % m
          out[length - 1 - bit // 8] |= 1 << (bit % 8)   # big-endian mask
      return out.hex()
  print(steering(bytes.fromhex("d65e64fa83f81cf7")))   # ...0012
  ```
- **Tests:** `crates/meshcop/src/crypto/pskc.rs` →
  `compute_bloom_filter_matches_spec_for_openthread_joiner`,
  `compute_bloom_filter_sets_two_crc_indexed_bits`.

---

## DTLS record protection — AES-128-CCM-8 (RFC 6655)

- **Proves:** a protected DTLS 1.2 application-data record's ciphertext and tag
  match an independent AES-128-CCM-8 implementation over this crate's RFC 6655
  nonce and additional-data layout.
- **Source:** Python [`cryptography`](https://cryptography.io)
  `AESCCM(tag_length=8)` (OpenSSL-backed).
- **Inputs:** key `000102030405060708090a0b0c0d0e0f`, fixed IV `a0a1a2a3`,
  epoch 1, sequence 7, content type 23 (application data), version `fefd`,
  plaintext `thread interop golden vector`. Nonce = `fixed_iv || epoch ||
  48-bit seq`; AAD = `epoch || 48-bit seq || type || version || plaintext_len`.
- **Expected record payload** (explicit nonce `0001000000000007` then
  ciphertext+tag):
  `0001000000000007` +
  `29d63f60549b8fd72853642698a75d5c84d1f291ab3d5928389398364042583c86865c8f`.
- **Regenerate:**
  ```python
  from cryptography.hazmat.primitives.ciphers.aead import AESCCM
  key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
  nonce = bytes.fromhex("a0a1a2a3") + bytes.fromhex("0001") + (7).to_bytes(6, "big")
  pt = b"thread interop golden vector"
  aad = bytes.fromhex("0001") + (7).to_bytes(6, "big") + bytes([23]) + bytes.fromhex("fefd") + len(pt).to_bytes(2, "big")
  print((nonce[4:] + AESCCM(key, tag_length=8).encrypt(nonce, pt, aad)).hex())
  ```
- **Test:** `crates/meshcop-dtls/src/tests/keys.rs` →
  `record_protection_matches_openssl_aes_ccm_8_vector`.

---

## Coverage gaps

These are validated by self-consistency today; an external golden is planned:

- **Raw AES-128-CCM-8 KAT.** The record vector above checks the full record
  layout; a NIST CCM known-answer test for the bare primitive would add a
  layout-independent check.
