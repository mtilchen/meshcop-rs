# Intentional mutation exclusions

`cargo-mutants` is run against the high-risk protocol files (see
`tools/ci/mutants.sh`, `targeted` scope). The CI gate fails on missed and
timed-out mutants. The exclusions below mirror `.cargo/mutants.toml` and state
the specific equivalence, observability, or diagnostic-contract rationale for
each one; every other viable mutant must be killed by the test suite.

## Equivalent mutants (no input distinguishes them)

- `crates/thread-dtls/src/driver.rs` `DtlsReplayWindow::mark_seen`, `>` → `>=`
  and `| 1` → `^ 1`. For `>` → `>=`, an equal sequence takes the slide arm
  with a zero shift instead of the in-window arm; both preserve the bitmap,
  set bit zero, and retain the same newest sequence. For `| 1` → `^ 1`, the
  slide arm has a shift of at least one, so bit zero is clear before the
  operation and OR and XOR produce the same value.
- `crates/ot-commissioner-rs/src/meshcop/diag/decode.rs`
  `decode_child_table`, `<< 8 | low` → `<< 8 ^ low`. The 9th child-ID bit
  (`<< 8`) and the low byte occupy disjoint bit ranges, so `|` and `^` produce
  the same value.
- `crates/ot-commissioner-rs/src/meshcop/coap.rs` CoAP header composition,
  `|` → `^`. The version, type, and token-length values occupy disjoint bit
  fields after their bounds are validated, so OR and XOR produce the same byte.
- `crates/ot-commissioner-rs/src/meshcop/coap.rs` option-header composition,
  `|` → `^`. The delta and length values occupy disjoint four-bit nibbles, so
  OR and XOR are identical.
- `crates/ot-commissioner-rs/src/commissioner/joiner.rs`
  `JoinerHandler::on_joiner_connected` default `→ ()` and
  `on_joiner_finalize` default `→ true`. The provided defaults are already a
  no-op and a constant `true`, so the mutations are byte-for-byte equivalent.

## Intrinsic / unobservable

- `crates/thread-dtls/src/ecjpake/mod.rs` `Drop for EcJpakeParty` → `()`. The
  body only zeroizes private scalars immediately before their storage is freed;
  observing the mutation would require reading freed memory with unsafe code.

## Intentionally uncontracted diagnostics

- `crates/ot-commissioner-rs/src/commissioner/client/mod.rs`
  `commissioner_trace` → `()`. Tracing is a best-effort `eprintln!` gated on
  `OT_COMMISSIONER_TRACE`. Its text and presence are deliberately not part of
  the program's behavioral contract.

There are no infrastructure-deferred or timeout exclusions. Such outcomes
fail the mutation gate.
