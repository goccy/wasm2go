package gcasm

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	// arm64 numeric branch: `B<cond>\t<off>` / `JMP\t<off>`. gc prints
	// conditional branches as BEQ/BNE/BLT/BHI/... and unconditional as
	// JMP. The stack-check branch is BLS.
	a64BranchRe = regexp.MustCompile(`^(B[A-Z]+|JMP|CBZ|CBNZ|CBZW|CBNZW|TBZ|TBNZ)\t(.*\b)(\d+)$`)
	a64CallRe   = regexp.MustCompile(`^CALL\t([^\s(]+)\(SB\)$`)
	// Jump table: `MOVD\t$pkg.fn.jumpN(SB), R0` then `MOVD\t(R0)(Ri<<3), R27`
	// then `JMP\t(R27)`.
	a64JtLeaqRe = regexp.MustCompile(`^MOVD\t\$([^\s(]+\.jump\d+)\(SB\), (R[0-9]+)$`)
	a64JtLdrRe  = regexp.MustCompile(`^MOVD\t\((R[0-9]+)\)\((R[0-9]+)<<3\), (R[0-9]+)$`)
	a64JtJmpRe  = regexp.MustCompile(`^JMP\t\((R[0-9]+)\)$`)
	// Float const rodata: `FMOVS\t$f32.<bits>(SB), Fn` / FMOVD f64.
	a64FconstRe = regexp.MustCompile(`\$f(32|64)\.([0-9a-f]+)\(SB\)`)
	// Named frame slot: `pkg.name<+->N(SP)` or `pkg.name(SP)`. gc's
	// local names include import paths and autotmp tildes
	// (`pkg.~408(SP)`), so the char class covers `~` too.
	a64NamedSlotRe = regexp.MustCompile(`[A-Za-z_.·~][A-Za-z0-9_./·~]*(?:([+\-]\d+))?\(SP\)`)
	// FP-relative arg reference: `pkg.name(FP)` / `pkg.name+N(FP)`.
	a64FPRe = regexp.MustCompile(`[A-Za-z_.·~][A-Za-z0-9_./·~]*(?:([+\-]\d+))?\(FP\)`)
	// Hardware-SP reference with a plain numeric offset: `N(RSP)`. gc
	// emits these for ABIInternal outgoing stack-args it spills below a
	// call (e.g. `MOVW R16, 8(RSP)`); base+index memory ops like
	// `(R4)(R20)` never contain `(RSP)` so this only matches real SP
	// slots. The leading boundary avoids matching a register name.
	a64HWSPRe = regexp.MustCompile(`(^|[\s,(])(\d+)\(RSP\)`)
	// runtime symbol (call or data).
	a64RuntimeRe = regexp.MustCompile(`\bruntime\.([A-Za-z0-9_]+)\(SB\)`)
)

// TransformARM64 rewrites one captured arm64 ABIInternal function into
// a shippable ABI0 .s body, mirroring the amd64 Transform: strip the
// captured prologue/epilogue/stacksplit and regenerate them from the
// declared frame; load FP args into ABIInternal registers at entry;
// marshal every internal CALL to the ABI0 stack convention; rewrite
// jump tables, float constants, runtime calls, and branch labels.
func TransformARM64(fn *Fn, opts TransformOptions) (string, error) {
	// DUFFZERO/DUFFCOPY cannot be hand-assembled (see errUnsupportedDuff);
	// such functions are routed to their pure fallback by Build.
	if hasDuffPseudo(fn.Insns) {
		return "", errUnsupportedDuff
	}
	var meat []Insn
	for _, in := range fn.Insns {
		if strings.HasPrefix(in.Text, "FUNCDATA") || strings.HasPrefix(in.Text, "PCDATA") {
			continue
		}
		meat = append(meat, in)
	}
	insns, err := a64StripPrologueEpilogue(meat)
	if err != nil {
		return "", fmt.Errorf("%s: %w", fn.Name, err)
	}

	resolveCallee := func(sym string) ([]ArgKind, bool, ArgKind, string, bool) {
		if params, hasRes, res, localSym, ok := opts.CalleeSig(sym); ok {
			return params, hasRes, res, localSym, true
		}
		if rm, ok := runtimeMarshalled[sym]; ok {
			return rm.params, rm.hasRes, rm.res, a64RuntimeRe.ReplaceAllString(sym+"(SB)", "runtime·$1"), true
		}
		return nil, false, 0, "", false
	}

	// Outgoing ABI0 argument scratch: max over marshalled callees.
	maxOut := 0
	for _, in := range insns {
		if m := a64CallRe.FindStringSubmatch(in.Text); m != nil {
			if params, hasRes, res, _, ok := resolveCallee(m[1]); ok {
				if sz := abi0ArgSize(params, hasRes, res); sz > maxOut {
					maxOut = sz
				}
			}
		}
	}
	maxOut = (maxOut + 15) &^ 15 // 16-align the outgoing ABI0 area

	// Frame = gc's local frame + outgoing ABI0 scratch. Virtual-SP
	// locals are top-relative, so growing the frame by maxOut re-homes
	// them above the hardware-RSP outgoing area (0..maxOut) without any
	// per-operand shift. `local` is passed to a64RewriteSlots only for
	// signature symmetry with the amd64 path (unused).
	// gc's reported frame INCLUDES the 16-byte saved FP/LR pair, but a
	// hand-written arm64 TEXT $F is EXCLUSIVE of it (the assembler adds
	// the STP save on top). So the local size is fn.FrameSize-16;
	// declared frame = locals + outgoing scratch.
	local := fn.FrameSize
	if local >= 16 {
		local -= 16
	}
	// Frame layout (low→high): [0:saved LR][8:outgoing ABI0 args
	// (maxOut)][8+maxOut:locals][top:saved FP]. Declared frame excludes
	// the FP/LR pair (the assembler adds it), so = 8 + maxOut + locals.
	frame := (8 + maxOut + local + 15) &^ 15

	var b strings.Builder
	abi0Args := abi0ArgSize(opts.Params, opts.HasResult, opts.Result)
	fmt.Fprintf(&b, "TEXT ·%s(SB), $%d-%d\n", opts.SymName, frame, abi0Args)
	b.WriteString("\tNO_LOCAL_POINTERS\n")

	args, res := assignARM64(opts.Params, opts.HasResult, opts.Result)
	for i, a := range args {
		if a.Reg == "" {
			return "", fmt.Errorf("gcasm arm64: param %d exceeds ABIInternal registers (pure fallback)", i)
		}
		fmt.Fprintf(&b, "\t%s %s+%d(FP), %s\n", loadForARM64(a.Kind), opts.argName(i), a.StackOf, a.Reg)
	}

	jtSites, err := a64FindJumpTables(fn.Name, insns, opts.Datas)
	if err != nil {
		return "", fmt.Errorf("%s: %w", fn.Name, err)
	}

	pool := opts.Consts
	ownPool := false
	if pool == nil {
		pool = &ConstPool{}
		ownPool = true
	}
	pkgPrefix := fn.Name[:strings.LastIndex(fn.Name, ".")+1]
	pkgSymRe := regexp.MustCompile(regexp.QuoteMeta(pkgPrefix) + `([A-Za-z_][A-Za-z0-9_]*)((?:[+\-]\d+)?\(SB\))`)

	// Branch targets.
	targets := map[int]bool{}
	for _, in := range insns {
		if m := a64BranchRe.FindStringSubmatch(in.Text); m != nil {
			var t int
			if _, err := fmt.Sscanf(m[3], "%d", &t); err == nil {
				targets[t] = true
			}
		}
	}
	for _, site := range jtSites {
		for _, r := range site.runs {
			targets[r.target] = true
		}
	}
	targetList := make([]int, 0, len(targets))
	for off := range targets {
		targetList = append(targetList, off)
	}
	sort.Ints(targetList)
	tptr := 0
	emitPending := func(upTo int) {
		for tptr < len(targetList) && targetList[tptr] <= upTo {
			fmt.Fprintf(&b, "pc%d:\n", targetList[tptr])
			tptr++
		}
	}

	for idx := 0; idx < len(insns); idx++ {
		in := insns[idx]
		emitPending(in.Off)
		if site, ok := jtSites[idx]; ok {
			a64EmitJumpTree(&b, site, in.Off)
			idx = site.jmpIdx
			continue
		}
		txt := in.Text
		// Numeric branch → label.
		if m := a64BranchRe.FindStringSubmatch(txt); m != nil {
			txt = m[1] + "\t" + m[2] + "pc" + m[3]
		}
		txt = a64RewriteSlots(txt, local, maxOut, args, opts)
		if m := a64CallRe.FindStringSubmatch(txt); m != nil {
			if params, hasRes, res2, localSym, ok := resolveCallee(m[1]); ok {
				// arm64 ABI0 outgoing args start at RSP+8 (RSP+0 holds
				// the saved LR), so every marshalled slot is offset +8.
				cargs, cres := assignARM64(params, hasRes, res2)
				for _, ca := range cargs {
					if ca.Reg != "" {
						fmt.Fprintf(&b, "\t%s %s, %d(RSP)\n", storeForARM64(ca.Kind), ca.Reg, ca.StackOf+8)
						continue
					}
					mov := "MOVD"
					if ca.Kind == ArgI32 || ca.Kind == ArgU32 || ca.Kind == ArgF32 {
						mov = "MOVW"
					}
					fmt.Fprintf(&b, "\t%s %d(RSP), R27\n", mov, ca.SeqOf+8+maxOut)
					fmt.Fprintf(&b, "\t%s R27, %d(RSP)\n", mov, ca.StackOf+8)
				}
				fmt.Fprintf(&b, "\tCALL %s(SB)\n", localSym)
				if hasRes {
					fmt.Fprintf(&b, "\t%s %d(RSP), %s\n", loadForARM64(cres.Kind), cres.StackOf+8, cres.Reg)
				}
				continue
			}
			if strings.HasPrefix(m[1], "runtime.") {
				if repl, ok := runtimeCallRewrites[m[1]]; ok {
					txt = "CALL\t" + repl + "(SB)"
				} else if runtimeAsmCallees[m[1]] {
					txt = a64RuntimeRe.ReplaceAllString(txt, "runtime·$1(SB)")
				} else {
					return "", fmt.Errorf("unhandled runtime call %q at +%d", m[1], in.Off)
				}
			} else {
				return "", fmt.Errorf("unmarshalled direct call %q at +%d", m[1], in.Off)
			}
		}
		// Type descriptor loads.
		if strings.Contains(txt, "type:") {
			m := regexp.MustCompile(`^MOVD\t\$?type:(.+)\(SB\), (R[0-9]+)$`).FindStringSubmatch(txt)
			if m == nil {
				return "", fmt.Errorf("unhandled type-descriptor operand %q at +%d", txt, in.Off)
			}
			if opts.Types == nil {
				return "", fmt.Errorf("type reference %q at +%d with no TypeTable", m[1], in.Off)
			}
			txt = fmt.Sprintf("MOVD\t·gcasmType%d(SB), %s", opts.Types.add(m[1]), m[2])
		}
		// Float constants.
		txt = a64FconstRe.ReplaceAllStringFunc(txt, func(m string) string {
			sub := a64FconstRe.FindStringSubmatch(m)
			return "·" + pool.add(sub[1], sub[2]) + "(SB)"
		})
		// runtime data operands.
		txt = a64RuntimeRe.ReplaceAllString(txt, "runtime·$1(SB)")
		// In-package symbol operands.
		txt = pkgSymRe.ReplaceAllString(txt, "·$1$2")
		if strings.HasPrefix(txt, "RET") && opts.HasResult {
			fmt.Fprintf(&b, "\t%s %s, %s+%d(FP)\n", storeForARM64(res.Kind), res.Reg, opts.resName(), res.StackOf)
		}
		fmt.Fprintf(&b, "\t%s\n", txt)
	}
	if tptr < len(targetList) {
		return "", fmt.Errorf("branch target +%d beyond last surviving instruction", targetList[tptr])
	}
	if ownPool && len(pool.names) > 0 {
		b.WriteString("\n")
		b.WriteString(pool.Emit())
	}
	return b.String(), nil
}

// a64RewriteSlots rewrites arm64 stack operands. arm64 addresses locals
// via the VIRTUAL SP pseudo-register (offsets measured DOWN from the
// frame top, e.g. `buf-1024(SP)`) — unlike amd64's hardware-RSP
// low-address offsets. Growing the frame by the outgoing-scratch area
// automatically re-homes virtual-SP locals (their top-relative offsets
// are unchanged), so local offsets are NOT shifted; only the symbol
// name is stripped, keeping the virtual `(SP)`. Incoming args stay
// `(FP)`. The marshalled outgoing args are written separately at
// hardware `N(RSP)` (0..maxOut, frame bottom).
func a64RewriteSlots(txt string, local, delta int, args []RegAssignment, opts TransformOptions) string {
	txt = a64FPRe.ReplaceAllStringFunc(txt, func(m string) string {
		sub := a64FPRe.FindStringSubmatch(m)
		off := 0
		if sub[1] != "" {
			if _, err := fmt.Sscanf(sub[1], "%d", &off); err != nil {
				return m
			}
		}
		for i, a := range args {
			if a.StackOf == off {
				return fmt.Sprintf("%s+%d(FP)", opts.argName(i), off)
			}
		}
		return fmt.Sprintf("%s+%d(FP)", opts.resName(), off)
	})
	// Hardware-SP outgoing-arg stores. gc places ABIInternal
	// stack-spilled outgoing args at hardware `N(RSP)` in the low frame
	// (the first at 8(RSP): RSP+0 holds the saved LR). Our regenerated
	// frame reserves [8, 8+delta) for OUR ABI0 outgoing scratch, so
	// shift gc's hardware refs up by delta to sit above it — this makes
	// gc's store land exactly where the call marshaller re-reads the
	// spilled arg (`SeqOf+8+delta`). Must run BEFORE the named-slot pass
	// below, which itself emits `(RSP)` operands that must not be
	// re-shifted. Mirrors the amd64 `n+delta` shift in rewriteSPOffsets.
	txt = a64HWSPRe.ReplaceAllStringFunc(txt, func(m string) string {
		sub := a64HWSPRe.FindStringSubmatch(m)
		var n int
		if _, err := fmt.Sscanf(sub[2], "%d", &n); err != nil {
			return m
		}
		return fmt.Sprintf("%s%d(RSP)", sub[1], n+delta)
	})
	// Virtual-SP local → HARDWARE RSP offset. gc addresses locals via
	// the virtual SP (top-of-frame relative, negative offsets), whose
	// placement for hand-written asm differs systematically from
	// gc-generated code. Convert to an absolute hardware offset:
	// hw = virtualOff + local + delta, which lands the local above the
	// outgoing scratch [0,delta) and below the saved FP/LR pair (the
	// declared frame is local+delta, and the assembler saves FP/LR at
	// [frame, frame+16)).
	txt = a64NamedSlotRe.ReplaceAllStringFunc(txt, func(m string) string {
		sub := a64NamedSlotRe.FindStringSubmatch(m)
		off := 0
		if sub[1] != "" {
			if _, err := fmt.Sscanf(sub[1], "%d", &off); err != nil {
				return m
			}
		}
		return fmt.Sprintf("%d(RSP)", off+local+8+delta)
	})
	return txt
}
