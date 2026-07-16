package wasm

// ValType is a wasm value type.
type ValType byte

const (
	ValI32       ValType = 0x7f
	ValI64       ValType = 0x7e
	ValF32       ValType = 0x7d
	ValF64       ValType = 0x7c
	ValV128      ValType = 0x7b
	ValFuncref   ValType = 0x70
	ValExternref ValType = 0x6f
)

func (v ValType) String() string {
	switch v {
	case ValI32:
		return "i32"
	case ValI64:
		return "i64"
	case ValF32:
		return "f32"
	case ValF64:
		return "f64"
	case ValV128:
		return "v128"
	case ValFuncref:
		return "funcref"
	case ValExternref:
		return "externref"
	}
	return "?"
}

// FuncType is a wasm function signature.
type FuncType struct {
	Params  []ValType
	Results []ValType
}

// Limits describes table or memory limits.
type Limits struct {
	Min    uint64
	Max    uint64
	HasMax bool
	Shared bool // threads proposal: memory declared shared (limits flag 0x02)
}

// TableType describes a table.
type TableType struct {
	ElemType ValType
	Limits   Limits
}

// MemoryType describes a memory.
type MemoryType struct {
	Limits Limits
	Is64   bool
}

// GlobalType describes a global's type and mutability.
type GlobalType struct {
	Type    ValType
	Mutable bool
}

// ImportKind selects the kind of an import.
type ImportKind byte

const (
	ImportFunc   ImportKind = 0x00
	ImportTable  ImportKind = 0x01
	ImportMemory ImportKind = 0x02
	ImportGlobal ImportKind = 0x03
	ImportTag    ImportKind = 0x04
)

// Import is a single import entry.
type Import struct {
	Module  string
	Name    string
	Kind    ImportKind
	TypeIdx uint32     // for ImportFunc
	Table   TableType  // for ImportTable
	Memory  MemoryType // for ImportMemory
	Global  GlobalType // for ImportGlobal
	Tag     Tag        // for ImportTag
}

// Tag is an exception-handling tag (section 13 / tag import). The
// exception-handling proposal models each `throw`able exception as a tag whose
// operand types are given by a function type (params = operands, results
// empty). Attribute is 0x00 for exceptions.
type Tag struct {
	Attribute byte
	TypeIdx   uint32 // index into Types; params are the exception's operand types
}

// ExportKind selects the kind of an export.
type ExportKind byte

const (
	ExportFunc   ExportKind = 0x00
	ExportTable  ExportKind = 0x01
	ExportMemory ExportKind = 0x02
	ExportGlobal ExportKind = 0x03
)

// Export is a single export entry.
type Export struct {
	Name  string
	Kind  ExportKind
	Index uint32
}

// Global is a defined global with an init expression.
type Global struct {
	Type GlobalType
	Init []byte // raw init expression bytes (terminating 0x0b included)
}

// Function is a defined wasm function. Body is the raw bytes of the function's
// "code" entry: locals declarations followed by the instruction stream and the
// terminating 0x0b. Codegen decodes on demand.
type Function struct {
	TypeIdx uint32
	Body    []byte
}

// ElementSegment is a (subset of) wasm element segment. We currently model
// active segments with a const-expr offset and a vec(funcidx) payload, the
// shape emitted by clang/wasi-libc for indirect-call tables. Other flavors
// panic at parse time.
type ElementSegment struct {
	TableIdx uint32
	Offset   []byte // raw const-expr including terminating 0x0b
	FuncIdxs []uint32
}

// DataSegment is a (subset of) wasm data segment. Active segments only.
type DataSegment struct {
	MemIdx uint32
	Offset []byte // raw const-expr including terminating 0x0b; nil when Passive
	Bytes  []byte
	// Passive segments (flag 0x01) have no offset: they sit inert until a
	// memory.init copies from them (data.drop then discards them). LLVM emits
	// ALL data passive for shared-memory builds — the threads proposal forbids
	// active segments re-initializing memory on every thread's instantiation —
	// and initializes exactly once from a __wasm_init_memory start function.
	Passive bool
}

// Module is the parsed in-memory representation of a wasm binary.
type Module struct {
	Types     []FuncType
	Imports   []Import
	Functions []Function
	Tables    []TableType
	Memories  []MemoryType
	Globals   []Global
	Exports   []Export
	Start     *uint32
	Elements  []ElementSegment
	Datas     []DataSegment
	Tags      []Tag // defined tags (section 13); tag index space is imported tags then these

	// Convenience: number of imported funcs (= count of Imports with Kind==ImportFunc).
	// Function index space is [imported funcs ...] then Functions[i].
	NumImportedFuncs   uint32
	NumImportedTables  uint32
	NumImportedMems    uint32
	NumImportedGlobals uint32
	NumImportedTags    uint32
}

// FuncTypeOf returns the function type at the given function index, accounting
// for imported functions.
func (m *Module) FuncTypeOf(idx uint32) FuncType {
	if idx < m.NumImportedFuncs {
		// Walk imports in order, picking the idx-th ImportFunc.
		var i uint32
		for _, imp := range m.Imports {
			if imp.Kind != ImportFunc {
				continue
			}
			if i == idx {
				return m.Types[imp.TypeIdx]
			}
			i++
		}
	}
	return m.Types[m.Functions[idx-m.NumImportedFuncs].TypeIdx]
}
