#!/usr/bin/env bash

set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
pushd "${script_directory}" >/dev/null
trap 'popd >/dev/null' EXIT

mkdir -p pkg
wasm-pack build --target web
cp static/index.html pkg/index.html
