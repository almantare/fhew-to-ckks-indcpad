#!/bin/sh
# Verify the formalization. Reuses a prebuilt Mathlib (read-only) from another local project;
# nothing is written outside this directory.
set -e
cd "$(dirname "$0")"
TC=~/.elan/toolchains/leanprover--lean4---v4.34.0-rc2/bin/lean
export LEAN_PATH="$(cat .leanpath)"
"$TC" LWEKeyRecovery.lean && echo "OK: LWEKeyRecovery.lean compiles with no errors"
"$TC" -o LWEKeyRecovery.olean LWEKeyRecovery.lean >/dev/null
LEAN_PATH="$LEAN_PATH:$(pwd)" "$TC" _axioms.lean
