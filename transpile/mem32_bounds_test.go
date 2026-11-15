package transpile_test

import (
	"strings"
	"testing"

	"github.com/goccy/wasm2go/transpile"
)

// TestMem32OutOfBoundsTraps pins the bounds of a wasm32 memory: an access
// whose bytes all lie below memory.size works, and one that reaches
// memory.size or past it traps — up to the last u32 address, and where
// the address plus the static offset passes 4 GiB (a 33-bit sum, which
// must not wrap around to the memory's start) — for plain loads and
// stores of every width, constant addresses, two loads off one address,
// a v128 access, before and after memory.grow (also a grow inside the
// accessing function). A trapped store writes nothing, and a store
// before a trapping load in the same function has happened. Where linear
// memory is a reservation the accesses past memory.size fault and the
// fault becomes the trap; elsewhere they compare with memory.size (run
// with GOFLAGS=-tags=wasm2go_boundschecks for that form). Both backends,
// as TestMem64OutOfBoundsTraps.
func TestMem32OutOfBoundsTraps(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts transpile.Options
	}{
		{name: "asm"},
		{name: "pure", opts: transpile.Options{PureOnly: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := runMem64(t, buildMem64With(t, "cg_mem32_bounds.wat", mem32BoundsMain, tc.opts))
			diffLines(t, got, strings.TrimSpace(mem32BoundsWant))
		})
	}
}

// diffLines reports every line where got and want differ.
func diffLines(t *testing.T, got, want string) {
	t.Helper()
	if got == want {
		return
	}
	gl, wl := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(gl) || i < len(wl); i++ {
		var g, w string
		if i < len(gl) {
			g = gl[i]
		}
		if i < len(wl) {
			w = wl[i]
		}
		if g != w {
			t.Errorf("line %d:\ngot:  %s\nwant: %s", i+1, g, w)
		}
	}
}

// mem32BoundsMain drives cg_mem32_bounds; addresses print relative to
// memory.size ("end").
const mem32BoundsMain = `	m := pkg.New()
	end := uint32(m.Size()) * 65536
	run := func(label string, f func() any) {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("%s: trap %v\n", label, r)
			}
		}()
		fmt.Printf("%s: %v\n", label, f())
	}
	type at struct {
		label string
		addr  uint32
	}
	edges := func(size uint32) []at {
		return []at{
			{"end-size", end - size},
			{"end-size+1", end - size + 1},
			{"end", end},
			{"2^31", 1 << 31},
			{"2^32-1", ^uint32(0)},
		}
	}
	a := func(x uint32) int32 { return int32(x) }
	for _, e := range edges(1) {
		run("load8 "+e.label, func() any { return m.Load8(a(e.addr)) })
	}
	for _, e := range edges(2) {
		run("load16 "+e.label, func() any { return m.Load16(a(e.addr)) })
	}
	for _, e := range edges(4) {
		run("load32 "+e.label, func() any { return m.Load32(a(e.addr)) })
	}
	for _, e := range edges(8) {
		run("load64 "+e.label, func() any { return m.Load64(a(e.addr)) })
		run("loadf64 "+e.label, func() any { return m.Loadf64(a(e.addr)) })
	}
	for _, e := range edges(20) {
		run("load32off "+e.label, func() any { return m.Load32off(a(e.addr)) })
	}
	run("load32off 2^32-16", func() any { return m.Load32off(a(^uint32(0) - 15)) })
	run("load32off 2^32-8", func() any { return m.Load32off(a(^uint32(0) - 7)) })
	run("load32far 0", func() any { return m.Load32far(0) })
	run("load32far 32", func() any { return m.Load32far(32) })
	run("constlow", func() any { return m.Constlow() })
	run("consthigh", func() any { return m.Consthigh() })
	run("constwrap", func() any { return m.Constwrap() })
	for _, e := range edges(16) {
		run("loadpair "+e.label, func() any { return m.Loadpair(a(e.addr)) })
		run("vload "+e.label, func() any { return m.Vload(a(e.addr)) })
	}
	for _, e := range edges(1) {
		run("store8 "+e.label, func() any { m.Store8(a(e.addr), 1); return "ok" })
	}
	for _, e := range edges(2) {
		run("store16 "+e.label, func() any { m.Store16(a(e.addr), 2); return "ok" })
	}
	for _, e := range edges(4) {
		run("store32 "+e.label, func() any { m.Store32(a(e.addr), 3); return "ok" })
	}
	for _, e := range edges(8) {
		run("store64 "+e.label, func() any { m.Store64(a(e.addr), 5); return "ok" })
	}
	for _, e := range edges(24) {
		run("store64off "+e.label, func() any { m.Store64off(a(e.addr), 6); return "ok" })
	}
	run("store64off 2^32-8", func() any { m.Store64off(a(^uint32(0)-7), 6); return "ok" })
	m.Store32(a(end-4), 0x11223344)
	run("store64 end-4", func() any { m.Store64(a(end-4), -1); return "ok" })
	run("after the trapped store, load32 end-4", func() any { return m.Load32(a(end - 4)) })
	run("storethenload end-7", func() any { return m.Storethenload(a(end-7), 9) })
	run("after it, load64 0", func() any { return m.Load64(0) })
	run("growload end", func() any { return m.Growload(a(end)) })
	run("size after growload", func() any { return m.Size() })
	run("grow 1", func() any { return m.Grow(1) })
	end = uint32(m.Size()) * 65536
	for _, e := range edges(1) {
		run("grown load8 "+e.label, func() any { return m.Load8(a(e.addr)) })
	}
	for _, e := range edges(8) {
		run("grown store64 "+e.label, func() any { m.Store64(a(e.addr), 10); return "ok" })
	}
	run("grown consthigh", func() any { return m.Consthigh() })
`

// mem32EdgeLines is edgeLines over mem32BoundsMain's edges.
func mem32EdgeLines(op, ok, trap string) string {
	var b strings.Builder
	for i, label := range []string{"end-size", "end-size+1", "end", "2^31", "2^32-1"} {
		res := trap
		if i == 0 {
			res = ok
		}
		b.WriteString(op + " " + label + ": " + res + "\n")
	}
	return b.String()
}

// mem32BoundsWant is what mem32BoundsMain prints.
var mem32BoundsWant = mem32EdgeLines("load8", "0", oob) +
	mem32EdgeLines("load16", "0", oob) +
	mem32EdgeLines("load32", "0", oob) +
	interleave(mem32EdgeLines("load64", "0", oob), mem32EdgeLines("loadf64", "0", oob)) +
	mem32EdgeLines("load32off", "0", oob) +
	"load32off 2^32-16: " + oob + "\n" +
	"load32off 2^32-8: " + oob + "\n" +
	"load32far 0: " + oob + "\n" +
	"load32far 32: " + oob + "\n" +
	"constlow: 0\n" +
	"consthigh: " + oob + "\n" +
	"constwrap: " + oob + "\n" +
	interleave(mem32EdgeLines("loadpair", "0", oob), mem32EdgeLines("vload", "0", voob)) +
	mem32EdgeLines("store8", "ok", oob) +
	mem32EdgeLines("store16", "ok", oob) +
	mem32EdgeLines("store32", "ok", oob) +
	mem32EdgeLines("store64", "ok", oob) +
	mem32EdgeLines("store64off", "ok", oob) +
	"store64off 2^32-8: " + oob + "\n" +
	"store64 end-4: " + oob + "\n" +
	"after the trapped store, load32 end-4: 287454020\n" +
	"storethenload end-7: " + oob + "\n" +
	"after it, load64 0: 9\n" +
	"growload end: 0\n" +
	"size after growload: 2\n" +
	"grow 1: 2\n" +
	mem32EdgeLines("grown load8", "0", oob) +
	mem32EdgeLines("grown store64", "ok", oob) +
	"grown consthigh: 0\n"
