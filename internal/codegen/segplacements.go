package codegen

import (
	"github.com/goccy/wasm2go/internal/lower"
	"github.com/goccy/wasm2go/internal/ssa"
)

// passiveSegmentPlacements recovers each passive data segment's
// static destination by walking the start section's lowered body (and
// its direct callees, shallowly) for memory.init ops with constant
// destinations. Shared-memory (threads) links emit ONLY passive
// segments, installed once at start-up with constant addresses — for
// the initial-image analyses here they are exactly as static as
// active segments. Cached: the scan lowers functions, which is not
// free.
func (t *translator) passiveSegmentPlacements() map[int]int64 {
	if t.segPlacements != nil {
		return t.segPlacements
	}
	t.segPlacements = map[int]int64{}
	if t.mod.Start == nil {
		return t.segPlacements
	}
	seen := map[uint32]bool{}
	var walk func(funcIdx uint32, depth int)
	walk = func(funcIdx uint32, depth int) {
		if depth > 3 || funcIdx < t.mod.NumImportedFuncs || seen[funcIdx] {
			return
		}
		if int(funcIdx-t.mod.NumImportedFuncs) >= len(t.mod.Functions) {
			return
		}
		seen[funcIdx] = true
		fn, err := lower.LowerFunction(t.mod, funcIdx, "segplacescan", nil)
		if err != nil {
			return
		}
		for _, blk := range fn.Blocks {
			for _, v := range blk.Values {
				switch v.Op {
				case ssa.OpMemoryInit:
					if len(v.Args) < 1 || v.Args[0] == nil {
						continue
					}
					dst := v.Args[0]
					switch dst.Op {
					case ssa.OpConst32:
						t.segPlacements[int(v.AuxInt)] = int64(uint32(dst.AuxInt))
					case ssa.OpConst64:
						t.segPlacements[int(v.AuxInt)] = dst.AuxInt
					}
				case ssa.OpCallDirect:
					if v.AuxInt >= 0 {
						walk(uint32(v.AuxInt), depth+1)
					}
				}
			}
		}
	}
	walk(*t.mod.Start, 0)
	return t.segPlacements
}
