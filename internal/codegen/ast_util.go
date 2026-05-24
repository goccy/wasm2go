package codegen

import (
	"go/ast"
	"go/token"
	"strconv"

	"github.com/goccy/wasm2go/internal/wasm"
)

// newID returns a *ast.Ident for the given name.
func newID(name string) *ast.Ident { return &ast.Ident{Name: name} }

// stringLit returns a quoted string literal expression.
func stringLit(s string) *ast.BasicLit {
	return &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(s)}
}

// intLit returns an integer literal expression.
func intLit(v int64) *ast.BasicLit {
	return &ast.BasicLit{Kind: token.INT, Value: strconv.FormatInt(v, 10)}
}

// uintLit returns an unsigned integer literal expression.
func uintLit(v uint64) *ast.BasicLit {
	return &ast.BasicLit{Kind: token.INT, Value: strconv.FormatUint(v, 10)}
}

// goTypeOf returns the Go type AST for the given wasm valtype.
func goTypeOf(v wasm.ValType) ast.Expr {
	switch v {
	case wasm.ValI32:
		return newID("int32")
	case wasm.ValI64:
		return newID("int64")
	case wasm.ValF32:
		return newID("float32")
	case wasm.ValF64:
		return newID("float64")
	case wasm.ValFuncref, wasm.ValExternref:
		return newID("any")
	}
	return newID("any")
}

// fieldList builds a *ast.FieldList from typed parameter pairs.
func fieldList(pairs ...field) *ast.FieldList {
	if len(pairs) == 0 {
		return nil
	}
	out := &ast.FieldList{}
	for _, p := range pairs {
		out.List = append(out.List, p.toASTField())
	}
	return out
}

type field struct {
	name string // empty for anonymous
	typ  ast.Expr
}

func (f field) toASTField() *ast.Field {
	af := &ast.Field{Type: f.typ}
	if f.name != "" {
		af.Names = []*ast.Ident{newID(f.name)}
	}
	return af
}

// isLocalName reports whether name matches `l<digits>`, the form used
// for wasm local-variable references in emitted Go.
func isLocalName(name string) bool {
	if len(name) < 2 || name[0] != 'l' {
		return false
	}
	for i := 1; i < len(name); i++ {
		if name[i] < '0' || name[i] > '9' {
			return false
		}
	}
	return true
}

// basicLitInt extracts the integer value of a (possibly unary-minus)
// BasicLit. Returns ok=false for non-integer literals or expressions
// that aren't a literal at all.
func basicLitInt(e ast.Expr) (int64, bool) {
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.SUB {
		v, ok := basicLitInt(u.X)
		if !ok {
			return 0, false
		}
		return -v, true
	}
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return 0, false
	}
	v, err := strconv.ParseInt(lit.Value, 0, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
