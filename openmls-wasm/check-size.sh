#!/usr/bin/env bash

set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
pushd "${script_directory}" >/dev/null
trap 'popd >/dev/null' EXIT

function die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

./build.sh

raw_size="$(tar c pkg | wc -c)"
gzip_size="$(tar cj pkg | wc -c)"

readonly raw_thresh=2000000
readonly gzip_thresh=650000

if ((raw_size > raw_thresh)); then
	die "raw size is too large: $raw_size > $raw_thresh"
else
	echo "raw size $raw_size is below threshold $raw_thresh"
fi

if ((gzip_size > gzip_thresh)); then
	die "gzip'd size is too large: $gzip_size > $gzip_thresh"
else
	echo "gzip'd size $gzip_size is below threshold $gzip_thresh"
fi
