package asmgen

// Emit-only sweep: lower and emit EVERY defined function of every
// fixture on BOTH emitters, asserting only that emission either
// succeeds or declines cleanly. The driver tests execute a curated
// subset natively; this sweep is what actually walks the emitters'
// long tails (both arch backends run regardless of the host arch —
// emission is pure code generation).

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/goccy/wasm2go/internal/lower"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

var emitSweepFixtures = []string{
	"arith", "control", "asmgen_widecmp", "brtable_switch",
	"cg_allops", "cg_atomics", "cg_bigdispatch", "cg_bittest",
	"cg_brtable64", "cg_brtable_bool", "cg_bulkmem", "cg_deadend",
	"cg_dispatchif", "cg_frame", "cg_globals", "cg_globals_nan",
	"cg_indirect", "cg_largeoff", "cg_manyfuncs", "cg_mem64",
	"cg_mem64_memops", "cg_mem64_simd_addrsum", "cg_mem64_simd_conv", "cg_mem64_simd_store",
	"cg_mem64big", "cg_memaddr", "cg_memops", "cg_memopt_shared",
	"cg_misc", "cg_negzero", "cg_negzero_flows", "cg_nestedloop",
	"cg_numerics", "cg_passive_data", "cg_recover", "cg_sharedexit",
	"cg_sharedimage", "cg_simd", "cg_simd_addrsum32", "cg_simd_conv32",
	"cg_simd_loop", "cg_simd_loopsum", "cg_simd_store32", "cg_specialfp",
	"cg_threads", "cg_threads_multiword", "cg_threads_musl_lock", "cg_threads_mutex",
	"cg_threads_visibility", "cg_threads_wake_dir", "cg_traps", "cg_unreachable",
	"cg_wasi",
}

func TestEmitSweepBothArches(t *testing.T) {
	for _, fixture := range emitSweepFixtures {
		t.Run(fixture, func(t *testing.T) {
			bin := testfixture.Wasm(t, fixture)
			mod, err := wasm.Parse(bytes.NewReader(bin))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			funcSymbol := func(idx uint32) string { return fmt.Sprintf("Fn%d", idx) }
			emitted, declined := 0, 0
			for i := range mod.Functions {
				funcIdx := mod.NumImportedFuncs + uint32(i)
				name := funcSymbol(funcIdx)
				fn, err := lower.LowerFunction(mod, funcIdx, name, nil)
				if err != nil {
					declined++
					continue
				}
				sig := mod.FuncTypeOf(funcIdx)
				opts := FuncOptions{ModulePkgRef: "*Module", Module: mod, FuncSymbol: funcSymbol}
				if asm, decl, err := EmitFuncAMD64(name, sig, fn, opts); err == nil {
					if asm == "" || decl == "" {
						t.Fatalf("amd64 %s: empty asm/decl", name)
					}
					emitted++
				} else {
					declined++
				}
				if asm, decl, err := EmitFuncARM64(name, sig, fn, opts); err == nil {
					if asm == "" || decl == "" {
						t.Fatalf("arm64 %s: empty asm/decl", name)
					}
					emitted++
				} else {
					declined++
				}
			}
			if emitted == 0 {
				// Some fixtures (atomics/threads) decline wholesale on
				// both emitters today; the sweep only requires that
				// emission never produces empty output when it claims
				// success.
				t.Skipf("all %d functions declined", declined)
			}
		})
	}
}
