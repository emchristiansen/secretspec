#!/usr/bin/env bash
# Test-only fake `op` CLI for the 1Password provider's unit tests.
#
# A real `op` would spend requests against a real 1Password account (and its
# rate limits). This one answers canned values and records every invocation,
# so unit tests can count exactly which `op` calls a provider operation makes.
#
# The harness installs the shim as `<dir>/op` and points SECRETSPEC_OPCLI_PATH
# at it; the shim keeps its state in that same directory:
#   invocations.log - one `argv: <arg> <arg> ...` line per call, appended
#                     before anything else so failing calls are logged too
#   <sub>.stderr    - when present, every `op <sub> ...` call prints this
#                     file to stderr and exits 1 (e.g. `read.stderr`,
#                     `vault.stderr`), driving the provider's error paths
set -euo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

{
  printf 'argv:'
  for arg in "$@"; do printf ' <%s>' "$arg"; done
  printf '\n'
} >> "$DIR/invocations.log"

# The provider sends `--account <name>` first when an account is configured.
if [ "${1:-}" = "--account" ]; then
  shift 2
fi

sub="${1:-}"

if [ -f "$DIR/$sub.stderr" ]; then
  cat "$DIR/$sub.stderr" >&2
  exit 1
fi

case "$sub" in
  vault)
    printf '[]'
    ;;
  read)
    printf 'shim-secret'
    ;;
  *)
    printf 'shim: unexpected op subcommand: %s\n' "$sub" >&2
    exit 1
    ;;
esac
