#!/usr/bin/env bash
# bundle-link-consumer.sh BUNDLE_DIR MODULE_PATH CONSUMER_DIR
#
# Link a consumer binary against a wasm2go multi-package bundle for every
# asm target. The consumer references every export dispatcher of the root
# package by value, so the linker's reachability closure covers the whole
# bundle (a blank import would let dead-code elimination skip it all —
# including the ABI-wrapper cycles this gate exists to catch). Only the
# link is exercised: the binaries are cross-compiled and discarded.
set -euo pipefail

bundle=$1
module=$2
consumer=$3

root_pkg=$(awk '/^package /{print $2; exit}' "$bundle"/*.go)
if [ -z "$root_pkg" ]; then
	echo "bundle-link-consumer: no root package in $bundle" >&2
	exit 1
fi
exports=$(grep -hoE '^func (Inv_[0-9]+_[0-9]+|New)\(' "$bundle"/*.go | sed -E 's/^func //; s/\($//' | sort -u)
if [ -z "$exports" ]; then
	echo "bundle-link-consumer: no export dispatchers found in $bundle" >&2
	exit 1
fi

mkdir -p "$consumer"
{
	printf 'module bundlelink\n\ngo 1.25.0\n\nrequire %s v0.0.0\n\nreplace %s => %s\n' "$module" "$module" "$bundle"
} > "$consumer/go.mod"
{
	printf 'package main\n\nimport bundle "%s"\n\nvar reach = []any{\n' "$module"
	for e in $exports; do
		printf '\tbundle.%s,\n' "$e"
	done
	printf '}\n\nfunc main() { _ = reach }\n'
} > "$consumer/main.go"
echo "bundle-link-consumer: $root_pkg — $(echo "$exports" | wc -l | tr -d ' ') export dispatchers reachable"

for target in "linux arm64 v1" "linux amd64 v2" "linux amd64 v1"; do
	set -- $target
	echo "bundle-link-consumer: linking GOOS=$1 GOARCH=$2 GOAMD64=$3"
	( cd "$consumer" && GOFLAGS=-mod=mod CGO_ENABLED=0 GOOS=$1 GOARCH=$2 GOAMD64=$3 go build -o /dev/null . )
done
echo "bundle-link-consumer: OK"
