# Helpful Information and Instructions for Agents

### Rust Development

- Avoid Rust nightly and unstable features unless explicitly approved.
- Prefer readability over cleverness or premature optimization.
- Design for flexibility, optionality, extensibility, refactorability, and clarity of intent.
- Keep public exported APIs minimal and well documented.
- Public APIs require module documentation.
- Do not reinvent the wheel when a well-implemented crate is appropriate, but keep dependencies small and justified for this project.
- Prefer `thiserror` derived error types.
- Prefer the builder pattern once argument length lints become a concern.
- Avoid `#[allow(...)]` unless explicitly approved.
- DRY should be observed without sacrificing readability or comprehensibility.
- Prefer well-abstracted modules over monolithic `lib.rs`, `mod.rs`, or oversized implementation files.

Work is not considered complete until:

- `cargo fmt --all --check` passes.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes.
- `cargo test --workspace --all-features` passes.

## Test Coverage Expectations

- Use `cargo-llvm-cov` for coverage reporting.
- Initial hard CI gates should be:
  - Global line coverage: at least 80%.
  - Global region coverage: at least 80%.
  - Global function coverage: at least 75%.
- Ratchet thresholds upward as the suite stabilizes:
  - Near-term target: 85% global line coverage.
  - Good target: 88-90% global line coverage.
  - Crypto/protocol modules: 90%+ where practical.
  - Parser-heavy modules: 90%+ plus fuzz or property tests.
- Do not chase 100% coverage when it would make tests brittle or low-value.
- Do not rely on global coverage alone. The stronger quality bar is behavioral:
  - No public commissioner operation should land without a deterministic scripted API test.
  - No parser that accepts wire data should land without malformed-input coverage.
  - Crypto and protocol state machines need negative-path tests, not only happy-path vectors.
  - Live border-router tests should remain ignored/gated by default and must not leak datasets, PSKc, network keys, or other secrets.
- When running live coverage against one border agent, run ignored live tests individually or serially to avoid concurrent commissioner-session conflicts.

### Test coverage and mutation testing

When changing Rust code, use `cargo-llvm-cov` and `cargo-mutants` together:

- Use `cargo-llvm-cov` to measure **wide coverage**: which code paths, branches, modules, features, and error cases are executed.

- Use `cargo-mutants` to measure **deep coverage**: whether the tests actually fail when the implementation is made wrong.

Coverage alone is not enough. A line can be covered while still having weak or missing assertions.
Use mutation results to identify tests that execute code without proving the behavior that matters.

Start with targeted mutation runs around changed modules before attempting whole-repo mutation testing.
Document surviving mutants in the review notes when they are intentionally deferred.

## Current Project Context

- This project is MeshCoP for Rust (`meshcop`), a pure Rust Thread MeshCoP
  commissioner implementation.
- The preferred production path is pure Rust with minimal external dependencies.
- OpenSSL, mbedTLS, OpenThread `ot-commissioner`, and CXX may be used as references or parity harnesses, but should not become required runtime dependencies without explicit review.
- The local live test border agent is `192.168.4.48:49156`.
- Live tests that compare the active dataset must use `ESP_MATTER_TEST_THREAD_DATASET_HEX` without printing or otherwise leaking secret dataset fields.
- Example apps and live tests should resign commissioner sessions before exit when they are only inspecting data.
- Mutating live operations must remain explicitly gated with `MESHCOP_MUTATE_OK=1`.

## Tooling Preferences

- Use `rg`/`rg --files` for searching before slower tools.
- Use `jq` for JSON handling when practical.
- Use `apply_patch` for manual file edits.
- Do not use destructive git commands unless explicitly requested.
- Use `gh` for GitHub interactions unless raw API calls are clearly better.
