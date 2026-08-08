package gcasm

// Register renumbering for fused pure-op bodies, arm64.
//
// The pair-table bodies read their operands from v0/v1 and leave the
// result in v0, so composing them inside a fused region costs a vector
// copy per operand in and one per parked result out. But every line of
// every body carries its own disassembly (this generator's output
// contract), and every mnemonic the fusable contract admits uses the
// standard NEON data-processing register layout — Rd at [4:0], Rn at
// [9:5], Rm at [20:16] — so the body can be re-encoded to read its
// operands STRAIGHT from the registers that hold them (pool slots,
// float homes, a chained v0) and write its final result straight to
// its destination. The copies disappear entirely.
//
// A tiny dataflow map handles multi-instruction bodies: reads of a
// logical register resolve to wherever its value currently lives, and
// mid-body writes claim the original v0..v3 scratch (always free in a
// fused region — real values live in the pool). Only the final
// value-producing write retargets to the destination. Anything the
// parser does not fully recognize — an unknown mnemonic, a non-WORD
// line, a destination-as-input instruction — falls back to the copy
// path, so renumbering can only be an optimization, never a semantics
// change.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// a64RenumOK lists mnemonics with the standard Rd/Rn/Rm field layout
// whose destination is write-only. Notably absent: bsl (destination is
// an input), tbl (register-list source), every GPR-crossing form
// (fmov/ins/umov — classified as builds/outs before renumbering), and
// ALL narrowing second-half forms (xtn2/sqxtn2/sqxtun2/uqxtn2/fcvtn2):
// they write only the destination's HIGH half and PRESERVE the low
// half their first-half twin produced — a destination-as-input that
// retargeting the final write silently corrupts. (The widening *2
// forms — sshll2, smull2, fcvtl2, ... — read the SOURCE's high half
// and write their destination whole, so they stay.)
var a64RenumOK = map[string]bool{
	"abs": true, "add": true, "addp": true, "and": true, "bic": true,
	"cmeq": true, "cmge": true, "cmgt": true, "cmhi": true, "cmhs": true,
	"cnt": true, "dup": true, "eor": true, "fabs": true, "fadd": true,
	"fcmeq": true, "fcmge": true, "fcmgt": true, "fcvtl": true, "fcvtl2": true,
	"fcvtn": true, "fcvtzs": true, "fcvtzu": true,
	"fdiv": true, "fmax": true, "fmin": true, "fmul": true, "fneg": true,
	"frintm": true, "frintn": true, "frintp": true, "frintz": true,
	"fsqrt": true, "fsub": true, "mov": true, "mul": true, "mvn": true,
	"neg": true, "orr": true, "saddlp": true, "saddlv": true, "scvtf": true,
	"shl": true, "smax": true, "smin": true, "smull": true, "smull2": true,
	"sqadd": true, "sqsub": true, "sqxtn": true,
	"sqxtun": true, "sshll": true, "sshll2": true,
	"sshr": true, "sub": true, "sxtl": true, "sxtl2": true, "uaddlp": true,
	"uaddlv": true, "ucvtf": true, "umax": true, "umin": true,
	"umull": true, "umull2": true, "uqadd": true, "uqsub": true,
	"uqxtn": true, "urhadd": true, "ushl": true,
	"ushll": true, "ushll2": true, "ushr": true, "usqadd": true,
	"uxtl": true, "uxtl2": true, "xtn": true,
}

// a64RenumLineRe splits a WORD body line into encoding and dis.
var a64RenumLineRe = regexp.MustCompile(`^WORD \$0x([0-9a-f]{8}) // (.+)$`)

// a64RenumVregRe matches a vector-register operand token in a dis
// (`v12.8h`, `v3.s[0]`, `d0`, `s1` scalar forms count too: the
// register field layout is the same).
var a64RenumVregRe = regexp.MustCompile(`^[vds](\d+)(\.[0-9a-z]+(\[\d+\])?)?$`)

// a64RenumberBody re-encodes core lines so operand reads come from
// srcs (physical registers per logical v0/v1/v2 operand) and the final
// v0 write lands in dst. Returns (rewritten, true) or (nil, false)
// when any line resists parsing — the caller then keeps the copy path.
func a64RenumberBody(core []string, srcs []int, dst int) ([]string, bool) {
	// cur maps logical registers (as the body was written: operands in
	// v0..v2, scratch above) to physical registers.
	cur := map[int]int{}
	for i, s := range srcs {
		cur[i] = s
	}
	// Find the last line that writes logical v0: that write retargets
	// to dst. (Scalar-result bodies never reach fusion.)
	lastV0Write := -1
	type parsed struct {
		enc  uint32
		ops  []string // operand tokens in dis order
		name string
		dis  string
	}
	ps := make([]parsed, len(core))
	for i, l := range core {
		m := a64RenumLineRe.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			return nil, false
		}
		enc64, err := strconv.ParseUint(m[1], 16, 32)
		if err != nil {
			return nil, false
		}
		dis := m[2]
		fields := strings.SplitN(dis, " ", 2)
		if len(fields) != 2 || !a64RenumOK[fields[0]] {
			return nil, false
		}
		var ops []string
		for _, tok := range strings.Split(fields[1], ",") {
			ops = append(ops, strings.TrimSpace(tok))
		}
		ps[i] = parsed{enc: uint32(enc64), ops: ops, name: fields[0], dis: dis}
		if d, ok := a64RenumVnum(ops[0]); ok && d == 0 {
			lastV0Write = i
		}
	}
	if lastV0Write == -1 {
		return nil, false
	}
	out := make([]string, len(core))
	for i, p := range ps {
		enc := p.enc
		newOps := make([]string, len(p.ops))
		copy(newOps, p.ops)
		// Vector operands map to fields by position: dest, then up to
		// two sources. Non-register tokens (immediates, GPRs) pass.
		vpos := 0
		for oi, tok := range p.ops {
			n, ok := a64RenumVnum(tok)
			if !ok {
				continue
			}
			var phys int
			if oi == 0 {
				// Destination write.
				if i == lastV0Write && n == 0 {
					phys = dst
				} else {
					phys = n // mid-body scratch keeps its slot (v0..v3 are free)
				}
			} else {
				if p, ok := cur[n]; ok {
					phys = p
				} else {
					phys = n
				}
			}
			switch vpos {
			case 0:
				enc = enc&^uint32(0x1F) | uint32(phys)
			case 1:
				enc = enc&^uint32(0x1F<<5) | uint32(phys)<<5
			case 2:
				enc = enc&^uint32(0x1F<<16) | uint32(phys)<<16
			default:
				return nil, false
			}
			newOps[oi] = a64RenumRetag(tok, phys)
			vpos++
		}
		// Update the dataflow AFTER sources resolved: the write claims
		// its scratch slot (or leaves the map alone for the final dst).
		if d, ok := a64RenumVnum(p.ops[0]); ok {
			if i == lastV0Write && d == 0 {
				delete(cur, 0)
			} else {
				cur[d] = d
			}
		}
		out[i] = fmt.Sprintf("WORD $0x%08x // %s %s (renum)", enc, p.name, strings.Join(newOps, ", "))
	}
	return out, true
}

// a64RenumVnum extracts the register number of a vector operand token.
func a64RenumVnum(tok string) (int, bool) {
	m := a64RenumVregRe.FindStringSubmatch(tok)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n > 31 {
		return 0, false
	}
	return n, true
}

// a64RenumRetag rewrites the register number inside an operand token.
func a64RenumRetag(tok string, phys int) string {
	m := a64RenumVregRe.FindStringSubmatch(tok)
	return tok[:1] + strconv.Itoa(phys) + tok[1+len(m[1]):]
}
