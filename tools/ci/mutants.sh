#!/usr/bin/env bash
set -euo pipefail

scope="${1:-${MUTANTS_SCOPE:-targeted}}"
shard="${MUTANTS_SHARD:-all}"
output_parent="${MUTANTS_OUTPUT_PARENT:-target/cargo-mutants}"
jobs="${CARGO_MUTANTS_JOBS:-2}"
minimum_timeout="${CARGO_MUTANTS_MINIMUM_TEST_TIMEOUT:-20}"

mkdir -p "${output_parent}"

if [[ "${scope}" == "skip" ]]; then
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "## Mutation Testing"
      echo
      echo "Skipped because \`MUTANTS_SCOPE=skip\`."
    } >> "${GITHUB_STEP_SUMMARY}"
  fi
  exit 0
fi

# Matrix runs split the normal targeted scope. Full/custom invocations still
# run exactly once on the primary shard so workflow_dispatch does not duplicate
# an intentionally unsharded audit.
if [[ "${scope}" != "targeted" && "${shard}" == "dtls" ]]; then
  echo "Mutation scope ${scope} runs only on the primary meshcop shard."
  exit 0
fi

filters=()
case "${scope}" in
  targeted)
    case "${shard}" in
      all)
        filters=(
          --file 'crates/meshcop/src/commissioner/client/*.rs'
          --file crates/meshcop/src/commissioner/joiner.rs
          --file crates/meshcop/src/meshcop/coap.rs
          --file 'crates/meshcop/src/meshcop/diag/*.rs'
          --file crates/meshcop/src/meshcop/parsers.rs
          --file crates/meshcop/src/meshcop/builders.rs
          --file crates/meshcop-dtls/src/driver.rs
          --file crates/meshcop-dtls/src/client_driver.rs
          --file crates/meshcop-dtls/src/server_driver.rs
          --file crates/meshcop-dtls/src/tokio_session.rs
          --file crates/meshcop-dtls/src/tokio_transport.rs
          --file crates/meshcop-dtls/src/handshake.rs
          --file crates/meshcop-dtls/src/thread_server_handshake.rs
          --file 'crates/meshcop-dtls/src/ecjpake/*.rs'
        )
        ;;
      meshcop)
        filters=(
          --file 'crates/meshcop/src/commissioner/client/*.rs'
          --file crates/meshcop/src/commissioner/joiner.rs
          --file crates/meshcop/src/meshcop/coap.rs
          --file 'crates/meshcop/src/meshcop/diag/*.rs'
          --file crates/meshcop/src/meshcop/parsers.rs
          --file crates/meshcop/src/meshcop/builders.rs
        )
        ;;
      dtls)
        filters=(
          --file crates/meshcop-dtls/src/driver.rs
          --file crates/meshcop-dtls/src/client_driver.rs
          --file crates/meshcop-dtls/src/server_driver.rs
          --file crates/meshcop-dtls/src/tokio_session.rs
          --file crates/meshcop-dtls/src/tokio_transport.rs
          --file crates/meshcop-dtls/src/handshake.rs
          --file crates/meshcop-dtls/src/thread_server_handshake.rs
          --file 'crates/meshcop-dtls/src/ecjpake/*.rs'
        )
        ;;
      *)
        echo "unknown MUTANTS_SHARD: ${shard}" >&2
        exit 2
        ;;
    esac
    ;;
  full)
    filters=()
    ;;
  custom)
    if [[ -z "${CARGO_MUTANTS_FILES:-}" ]]; then
      echo "MUTANTS_SCOPE=custom requires CARGO_MUTANTS_FILES" >&2
      exit 2
    fi
    read -r -a files <<< "${CARGO_MUTANTS_FILES}"
    for file in "${files[@]}"; do
      filters+=(--file "${file}")
    done
    ;;
  *)
    echo "unknown MUTANTS_SCOPE: ${scope}" >&2
    exit 2
    ;;
esac

set +e
cargo mutants \
  "${filters[@]}" \
  --all-features \
  --annotations github \
  --jobs "${jobs}" \
  --minimum-test-timeout "${minimum_timeout}" \
  --no-times \
  --output "${output_parent}"
mutants_status=$?
set -e

outcomes="${output_parent}/mutants.out/outcomes.json"
if [[ ! -f "${outcomes}" ]]; then
  echo "cargo-mutants did not produce ${outcomes}" >&2
  exit "${mutants_status}"
fi

total="$(jq -r '.total_mutants // 0' "${outcomes}")"
caught="$(jq -r '.caught // 0' "${outcomes}")"
missed="$(jq -r '.missed // 0' "${outcomes}")"
timeout="$(jq -r '.timeout // 0' "${outcomes}")"
unviable="$(jq -r '.unviable // 0' "${outcomes}")"
success="$(jq -r '.success // 0' "${outcomes}")"
version="$(jq -r '.cargo_mutants_version // "unknown"' "${outcomes}")"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## Mutation Testing"
    echo
    echo "Scope: \`${scope}\`"
    echo "Shard: \`${shard}\`"
    echo
    echo "| Outcome | Count |"
    echo "| --- | ---: |"
    echo "| Total mutants | ${total} |"
    echo "| Caught | ${caught} |"
    echo "| Missed | ${missed} |"
    echo "| Timed out | ${timeout} |"
    echo "| Unviable | ${unviable} |"
    echo "| Success baseline outcomes | ${success} |"
    echo
    echo "cargo-mutants version: \`${version}\`"
    echo
    if (( missed > 0 || timeout > 0 )); then
      echo "### Surviving or Timed-Out Mutants"
      echo
      jq -r '
        .outcomes[]
        | select((.summary == "Missed") or (.summary == "Timeout"))
        | select(.scenario.Mutant?)
        | "- `" + .scenario.Mutant.file + ":" + (.scenario.Mutant.span.start.line | tostring) + "` " + .scenario.Mutant.name
      ' "${outcomes}"
      echo
    fi
    echo "Artifact: \`${output_parent}/mutants.out/\`."
  } >> "${GITHUB_STEP_SUMMARY}"
fi

if (( missed > 0 || timeout > 0 )); then
  exit 1
fi

if (( mutants_status != 0 )); then
  exit "${mutants_status}"
fi
