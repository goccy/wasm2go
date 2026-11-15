//go:build unix && !wasm2go_boundschecks && !(386 || arm || mips || mipsle)

package transpile_test

// testReserved: the generated programs the tests build here hold linear
// memory as a reservation (the constraint is
// sharedimage.ReservedConstraint; the go subprocesses inherit GOFLAGS and
// so the same tags).
const testReserved = true
