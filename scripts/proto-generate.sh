#!/usr/bin/env bash
# Regenerates gen/ from this repo's proto/. Audit calls no other service, so
# no callee protos are fetched: STEWARD_CORE_REF in proto-refs.env pins the
# internal/workloadauth copy only. The scheduled proto-sync refresh runs this
# after it bumps a pin.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
buf generate
