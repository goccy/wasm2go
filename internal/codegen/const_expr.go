package codegen

import (
	"encoding/binary"
	"fmt"
	"go/ast"
	"go/token"
	"math"
	"strconv"
	"strings"

	"github.com/goccy/wasm2go/internal/wasm"
)

// evalConstExprI64 evaluates a wasm constant expression that must produce an
// integer value (i32 or i64). Used for data/element segment offsets and
// integer global initializers. global.get of an *imported* global is not yet
// supported (returns an error). The expression bytes include the trailing
// 0x0b end byte.
func evalConstExprI64(expr []byte, m *wasm.Module) (int64, error) {
	if len(expr) == 0 {
		return 0, fmt.Errorf("empty const expr")
	}
	op := expr[0]
	switch op {
	case 0x41: // i32.const
		v, _, err := readSLEB(expr[1:])
		if err != nil {
			return 0, err
		}
		return v, nil
	case 0x42: // i64.const
		v, _, err := readSLEB(expr[1:])
		if err != nil {
			return 0, err
		}
		return v, nil
	case 0x23: // global.get
		return 0, fmt.Errorf("global.get in const expr not yet supported")
	}
	return 0, fmt.Errorf("unsupported const-expr opcode 0x%02x", op)
}

// evalConstExprFloat evaluates a wasm constant expression that produces a
// float value (f32.const = 0x43, f64.const = 0x44). Returns the value as a
// float64; for f32 the caller narrows to float32. The expression bytes
// include the trailing 0x0b end byte.
func evalConstExprFloat(expr []byte) (float64, error) {
	if len(expr) == 0 {
		return 0, fmt.Errorf("empty const expr")
	}
	switch expr[0] {
	case 0x43: // f32.const — 4 little-endian bytes
		if len(expr) < 5 {
			return 0, fmt.Errorf("truncated f32.const")
		}
		bits := binary.LittleEndian.Uint32(expr[1:5])
		return float64(math.Float32frombits(bits)), nil
	case 0x44: // f64.const — 8 little-endian bytes
		if len(expr) < 9 {
			return 0, fmt.Errorf("truncated f64.const")
		}
		bits := binary.LittleEndian.Uint64(expr[1:9])
		return math.Float64frombits(bits), nil
	}
	return 0, fmt.Errorf("unsupported float const-expr opcode 0x%02x", expr[0])
}

// floatInitExpr builds a Go expression for a float global's initial value.
// Finite values use a decimal literal cast to the target type; NaN/Inf
// values route through math.Float{32,64}frombits since Go has no NaN/Inf
// literal syntax. isF32 selects between float32 and float64 emission.
func floatInitExpr(v float64, isF32 bool) ast.Expr {
	special := math.IsNaN(v) || math.IsInf(v, 0)
	if isF32 {
		if special {
			return &ast.CallExpr{
				Fun: &ast.SelectorExpr{X: newID("math"), Sel: newID("Float32frombits")},
				Args: []ast.Expr{&ast.BasicLit{
					Kind:  token.INT,
					Value: fmt.Sprintf("0x%x", math.Float32bits(float32(v))),
				}},
			}
		}
		return &ast.CallExpr{Fun: newID("float32"), Args: []ast.Expr{&ast.BasicLit{
			Kind:  token.FLOAT,
			Value: strconv.FormatFloat(v, 'g', -1, 32),
		}}}
	}
	if special {
		return &ast.CallExpr{
			Fun: &ast.SelectorExpr{X: newID("math"), Sel: newID("Float64frombits")},
			Args: []ast.Expr{&ast.BasicLit{
				Kind:  token.INT,
				Value: fmt.Sprintf("0x%x", math.Float64bits(v)),
			}},
		}
	}
	return &ast.CallExpr{Fun: newID("float64"), Args: []ast.Expr{&ast.BasicLit{
		Kind:  token.FLOAT,
		Value: strconv.FormatFloat(v, 'g', -1, 64),
	}}}
}

func readSLEB(b []byte) (int64, int, error) {
	var v int64
	var s uint
	var i int
	var by byte
	for i < len(b) {
		by = b[i]
		i++
		v |= int64(by&0x7f) << s
		s += 7
		if by&0x80 == 0 {
			break
		}
		if s > 70 {
			return 0, i, fmt.Errorf("sleb overflow")
		}
	}
	if s < 64 && (by&0x40) != 0 {
		v |= -1 << s
	}
	return v, i, nil
}

// goEscapedBytes returns a Go string-literal representation (double-quoted,
// with \xNN escapes) of the given bytes.
func goEscapedBytes(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b)*4 + 2)
	sb.WriteByte('"')
	for _, c := range b {
		switch {
		case c == '\\':
			sb.WriteString(`\\`)
		case c == '"':
			sb.WriteString(`\"`)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\t':
			sb.WriteString(`\t`)
		case c == '\r':
			sb.WriteString(`\r`)
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		default:
			fmt.Fprintf(&sb, `\x%02x`, c)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}
