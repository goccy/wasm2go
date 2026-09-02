#!/usr/bin/env bash
# bundle-link-consumer.sh BUNDLE_DIR MODULE_PATH CONSUMER_DIR
#
# Link consumer binaries against a wasm2go multi-package bundle for every
# asm target. Two consumers are generated and each is linked for each
# target:
#
#   - every consumer references every export dispatcher of the root
#     package by value, so the linker's reachability closure covers the
#     whole bundle (a blank import would let dead-code elimination skip
#     it all — including the ABI-wrapper cycles this gate exists to
#     catch);
#   - the consumers import the chunk packages (pN) explicitly, one in
#     ascending and one in descending order. The linker resolves DUPOK
#     symbols first-come, so a defect that depends on which package loads
#     first (a wrapper emitted under another package's symbol name)
#     fires only for one relative order of the two packages; between the
#     two orders every pair of chunk packages is seen both ways, so the
#     check does not depend on the production consumer's import graph.
#
# Only the link is exercised: the binaries are cross-compiled and
# discarded.
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
chunks=$(cd "$bundle" && ls -d p[0-9]* 2>/dev/null | sort -V || true)
if [ -z "$chunks" ]; then
	echo "bundle-link-consumer: no chunk packages (pN) in $bundle — single-package bundle, importing the root only" >&2
fi
chunks_desc=$(echo "$chunks" | sort -rV)

mkdir -p "$consumer"
{
	printf 'module bundlelink\n\ngo 1.25.0\n\nrequire %s v0.0.0\n\nreplace %s => %s\n' "$module" "$module" "$bundle"
} > "$consumer/go.mod"
gen_main() { # gen_main DIR "chunk list in import order"
	mkdir -p "$consumer/$1"
	{
		printf 'package main\n\nimport (\n'
		for c in $2; do
			printf '\t_ "%s/%s"\n' "$module" "$c"
		done
		printf '\tbundle "%s"\n)\n\nvar reach = []any{\n' "$module"
		for e in $exports; do
			printf '\tbundle.%s,\n' "$e"
		done
		printf '}\n\nfunc main() { _ = reach }\n'
	} > "$consumer/$1/main.go"
}
gen_main ascending "$chunks"
gen_main descending "$chunks_desc"
echo "bundle-link-consumer: $root_pkg — $(echo "$exports" | wc -l | tr -d ' ') export dispatchers reachable, chunk orders: [$(echo $chunks)] and [$(echo $chunks_desc)]"

for target in "linux arm64 v1" "linux amd64 v2" "linux amd64 v1"; do
	set -- $target
	for order in ascending descending; do
		echo "bundle-link-consumer: linking GOOS=$1 GOARCH=$2 GOAMD64=$3 ($order chunk import order)"
		( cd "$consumer" && GOFLAGS=-mod=mod CGO_ENABLED=0 GOOS=$1 GOARCH=$2 GOAMD64=$3 go build -o /dev/null ./$order )
	done
done
echo "bundle-link-consumer: OK"
