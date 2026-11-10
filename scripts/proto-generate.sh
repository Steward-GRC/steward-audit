#!/usr/bin/env bash
# Regenerates gen/ from this repo's proto/. Audit calls no other service, so
# no callee protos are fetched and there is no proto-refs.env to pin.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
buf generate
