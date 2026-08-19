# Security Policy

MeshCoP for Rust is a Thread MeshCoP commissioner. It handles highly
sensitive material — the commissioner credential (PSKc), joiner credentials
(PSKd), the Thread network key and full operational datasets, EC J-PAKE private
scalars, and derived DTLS session keys. We take reports about it seriously and
aim to handle them responsibly.

## Supported Versions

The crate is pre-1.0. Security fixes are made against the latest published `0.x`
release and `main`. Older `0.x` lines do not receive backports.

| Version | Supported          |
| ------- | ------------------ |
| `0.x` (latest) | :white_check_mark: |
| older `0.x`    | :x:                |

## Reporting a Vulnerability

Please report suspected vulnerabilities **privately** — do not open a public
issue, pull request, or discussion for a security problem.

Preferred channel: GitHub **private vulnerability reporting**
(repository → *Security* → *Report a vulnerability*).

Fallback: email the maintainer at `matt@tilchen.net` and put
`[MeshCoP for Rust security]` in the subject. PGP can be arranged on request.

Please include enough to reproduce: affected version/commit, a minimal input or
test, and the observed vs. expected behavior. **Never include real PSKc, network
keys, or operational datasets in a report** — synthesize equivalent test values
or redact secrets.

What to expect:

- Acknowledgement within **3 business days**.
- An initial assessment (severity, affected versions) within **10 business
  days**.
- Coordinated disclosure: we will agree on a disclosure timeline with the
  reporter and credit reporters who wish to be named.

There is no paid bug-bounty program for this project.

## Threat Model

### Assets

- **PSKc** — the commissioner credential.
- **PSKd** — a joiner's commissioning credential.
- **Thread network key** and **active/pending operational datasets**.
- **EC J-PAKE private scalars** and **derived DTLS session / record-protection
  keys**.

### Security goals and built-in mitigations

- **Secret hygiene.** Library-owned PSKc, PSKd, J-PAKE scalars, datasets, and
  record-protection keys are redacted in `Debug` output and best-effort
  zeroized when replaced or dropped (`zeroize`). Explicit raw access exposes
  borrowed secret views, while owned encodings and typed copies become
  caller-managed values. Examples redact dataset secrets by default and only
  print raw secrets behind an explicit opt-in.
- **Memory safety.** The crate contains **no `unsafe` code**.
- **Constant-time primitives** are used where applicable (`subtle` and the
  underlying RustCrypto crates) to avoid obvious secret-dependent branching in
  comparison/selection. See "Out of scope" for the limits of this claim.
- **Protocol protection.** DTLS 1.2 with EC J-PAKE authentication over PSKc and
  AES-128-CCM-8 record protection per the Thread specification, including a
  64-bit sliding-window anti-replay filter.
- **Hardened parsers.** Every wire parser (TLV, dataset, CoAP, DTLS
  record/handshake, EC J-PAKE codecs) has a coverage-guided fuzz target. The
  highest-risk protocol paths also gate on targeted mutation testing;
  malformed input must return an error rather than panic, hang, over-read, or
  leak.
- **Safe-by-default operations.** Mutating live operations are gated behind
  `MESHCOP_MUTATE_OK=1`, and read-only example/inspection paths resign
  the commissioner session before exit.

### In scope (threats we defend against)

- Malformed or adversarial wire input to any parser → errors, never panics,
  hangs, unbounded allocation, or out-of-bounds reads.
- A passive on-path network attacker → DTLS confidentiality and integrity, and
  EC J-PAKE password-authenticated key agreement over PSKc.
- Replay of captured DTLS records → rejected by the anti-replay window.
- Accidental disclosure of secrets through `Debug`/logging in normal use.

### Out of scope / non-goals

We are explicit about what this library does **not** claim to protect against:

- **Physical, host, or supply-chain compromise** of the machine running the
  commissioner, and the quality of the OS CSPRNG (randomness is sourced via
  `getrandom`).
- **Advanced side channels.** Beyond using constant-time primitives, the crate
  is not hardened against power, EM, microarchitectural, or cache-timing
  attacks, nor against a hostile co-resident attacker. Timing guarantees inherit
  from upstream crates and are not independently verified here.
- **A malicious or compromised border agent**, beyond what the Thread protocol
  itself authenticates.
- **CCM (token/certificate) commissioning flows**, which are intentionally not
  implemented and return `Error::Unsupported`.
- **Independent audit status.** As of this writing the crate has **not** had a
  third-party security or cryptographic audit. Treat the cryptographic and
  protocol code accordingly until that changes.

## Handling secrets when using this crate

- Do not log datasets, PSKc, or PSKd. Rely on the redaction defaults; only
  export or print raw secrets in controlled debugging contexts, and treat
  borrowed raw views and returned owned values as exposed secret material.
- Keep live, mutating operations behind `MESHCOP_MUTATE_OK=1`.
- Live border-router tests are `#[ignore]` by default and must not print or
  otherwise leak datasets, PSKc, or network keys.
