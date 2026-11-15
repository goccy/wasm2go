//go:build !(unix && !wasm2go_boundschecks && !(386 || arm || mips || mipsle))

package transpile_test

// testReserved: see mem_fault_reserved_test.go.
const testReserved = false
