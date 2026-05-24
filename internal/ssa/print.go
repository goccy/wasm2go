package ssa

import (
	"fmt"
	"strings"
)

// FuncString renders a Func as a multiline IR dump, modeled on
// cmd/compile/internal/ssa's `compile -d=ssa/all/dump` output but
// simpler. Format:
//
//	func Name(p0 i32, p1 i32) i32 {
//	  b0:
//	    v1 = OpParam [0] : i32
//	    v2 = OpParam [1] : i32
//	    v3 = OpAdd32 v1 v2 : i32
//	    Plain → b1
//	  b1:
//	    v4 = OpCopy v3 : i32
//	    Ret
//	}
//
// The dump is the source of truth for golden-file tests on passes.
func FuncString(f *Func) string {
	var b strings.Builder
	fmt.Fprintf(&b, "func %s(", f.Name)
	for i, p := range f.Sig.Params {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "p%d %s", i, p)
	}
	b.WriteString(") ")
	if len(f.Sig.Results) == 1 {
		b.WriteString(f.Sig.Results[0].String())
	} else if len(f.Sig.Results) > 1 {
		b.WriteString("(")
		for i, r := range f.Sig.Results {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(r.String())
		}
		b.WriteString(")")
	}
	b.WriteString(" {\n")
	for _, blk := range f.Blocks {
		fmt.Fprintf(&b, "  b%d:\n", blk.ID)
		if len(blk.Preds) > 0 {
			b.WriteString("    ; preds=")
			for i, e := range blk.Preds {
				if i > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, " b%d", e.Block.ID)
			}
			b.WriteString("\n")
		}
		for _, v := range blk.Values {
			fmt.Fprintf(&b, "    %s : %s\n", v.String(), v.Type)
		}
		switch blk.Kind {
		case BlockPlain:
			if len(blk.Succs) > 0 {
				fmt.Fprintf(&b, "    Plain → b%d\n", blk.Succs[0].Block.ID)
			} else {
				b.WriteString("    Plain → <none>\n")
			}
		case BlockIf:
			thenID, elseID := BlockID(-1), BlockID(-1)
			if len(blk.Succs) > 0 {
				thenID = blk.Succs[0].Block.ID
			}
			if len(blk.Succs) > 1 {
				elseID = blk.Succs[1].Block.ID
			}
			ctrlID := ValueID(0)
			if blk.Control != nil {
				ctrlID = blk.Control.ID
			}
			fmt.Fprintf(&b, "    If v%d → b%d, b%d\n", ctrlID, thenID, elseID)
		case BlockRet:
			b.WriteString("    Ret\n")
		case BlockUnreachable:
			b.WriteString("    Unreachable\n")
		default:
			fmt.Fprintf(&b, "    %s\n", "<invalid block kind>")
		}
	}
	b.WriteString("}\n")
	return b.String()
}
