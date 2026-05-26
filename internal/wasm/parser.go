package wasm

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
)

// maxSectionPayload caps the total bytes any single wasm section can
// declare. The wasm spec permits sizes up to 4 GiB minus one, but
// every section we actually accept (types, code, data, ...) fits
// well below 256 MiB in practice; refusing larger payloads up front
// blocks a maliciously-crafted u32 LEB128 from making the parser
// allocate or read multi-gigabyte buffers before failing on a
// downstream invariant.
const maxSectionPayload = 1 << 28 // 256 MiB

// maxVectorLen caps the count field of any vec(...) in a section
// payload. Tied to maxSectionPayload — a vector that big could not
// fit in a single section even if every element were one byte.
const maxVectorLen = maxSectionPayload

// maxFunctionBody caps the byte size of a single function body in the
// code section. The largest real-world wasm function (LLVM IR bundles,
// generated SQL parsers) is far under 32 MiB; this guard blocks a
// crafted LEB128 size field from forcing a multi-gigabyte allocation
// before io.ReadFull would have truncated.
const maxFunctionBody = 1 << 25 // 32 MiB

// Parse reads a WebAssembly binary from r and returns the parsed Module.
// Function bodies are kept as raw byte slices.
func Parse(r io.Reader) (*Module, error) {
	br := &readerAt{r: bufio.NewReader(r)}
	if err := readHeader(br); err != nil {
		return nil, err
	}
	m := &Module{}
	for {
		id, err := br.ReadByte()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		size, err := readU32(br)
		if err != nil {
			return nil, fmt.Errorf("section %d: read size: %w", id, err)
		}
		if size > maxSectionPayload {
			return nil, fmt.Errorf("section %d: payload size %d exceeds %d-byte safety cap", id, size, maxSectionPayload)
		}
		raw := make([]byte, size)
		if _, err := io.ReadFull(br, raw); err != nil {
			return nil, fmt.Errorf("section %d: read payload: %w", id, err)
		}
		sr := &readerAt{r: bufio.NewReader(bytes.NewReader(raw))}
		if err := parseSection(m, id, sr, raw); err != nil {
			return nil, fmt.Errorf("section %d: %w", id, err)
		}
	}
	// Compute import counts.
	for _, imp := range m.Imports {
		switch imp.Kind {
		case ImportFunc:
			m.NumImportedFuncs++
		case ImportTable:
			m.NumImportedTables++
		case ImportMemory:
			m.NumImportedMems++
		case ImportGlobal:
			m.NumImportedGlobals++
		}
	}
	return m, nil
}

func readHeader(r byteReader) error {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	if hdr[0] != 0x00 || hdr[1] != 0x61 || hdr[2] != 0x73 || hdr[3] != 0x6d {
		return fmt.Errorf("not a wasm binary (bad magic % x)", hdr[:4])
	}
	if hdr[4] != 0x01 || hdr[5] != 0x00 || hdr[6] != 0x00 || hdr[7] != 0x00 {
		return fmt.Errorf("unsupported wasm version % x", hdr[4:])
	}
	return nil
}

func parseSection(m *Module, id byte, r byteReader, raw []byte) error {
	switch id {
	case 0:
		// Custom section: name + bytes. Ignored for now.
		return nil
	case 1:
		return parseTypeSection(m, r)
	case 2:
		return parseImportSection(m, r)
	case 3:
		return parseFunctionSection(m, r)
	case 4:
		return parseTableSection(m, r)
	case 5:
		return parseMemorySection(m, r)
	case 6:
		return parseGlobalSection(m, r)
	case 7:
		return parseExportSection(m, r)
	case 8:
		idx, err := readU32(r)
		if err != nil {
			return err
		}
		m.Start = &idx
		return nil
	case 9:
		return parseElementSection(m, r)
	case 10:
		return parseCodeSection(m, r)
	case 11:
		return parseDataSection(m, r)
	case 12:
		// DataCount: just a u32; we don't need it because we read the data section directly.
		_, err := readU32(r)
		return err
	default:
		return fmt.Errorf("unknown section id %d", id)
	}
}

func parseTypeSection(m *Module, r byteReader) error {
	n, err := readU32(r)
	if err != nil {
		return err
	}
	if n > maxVectorLen {
		return fmt.Errorf("type section: count %d exceeds %d-element cap", n, maxVectorLen)
	}
	m.Types = make([]FuncType, n)
	for i := uint32(0); i < n; i++ {
		tag, err := r.ReadByte()
		if err != nil {
			return err
		}
		if tag != 0x60 {
			return fmt.Errorf("type[%d]: bad tag 0x%02x (want 0x60)", i, tag)
		}
		ft, err := readFuncType(r)
		if err != nil {
			return fmt.Errorf("type[%d]: %w", i, err)
		}
		m.Types[i] = ft
	}
	return nil
}

func readFuncType(r byteReader) (FuncType, error) {
	np, err := readU32(r)
	if err != nil {
		return FuncType{}, err
	}
	if np > maxVectorLen {
		return FuncType{}, fmt.Errorf("functype params count %d exceeds %d-element cap", np, maxVectorLen)
	}
	params := make([]ValType, np)
	for i := uint32(0); i < np; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return FuncType{}, err
		}
		params[i] = ValType(b)
	}
	nr, err := readU32(r)
	if err != nil {
		return FuncType{}, err
	}
	if nr > maxVectorLen {
		return FuncType{}, fmt.Errorf("functype results count %d exceeds %d-element cap", nr, maxVectorLen)
	}
	results := make([]ValType, nr)
	for i := uint32(0); i < nr; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return FuncType{}, err
		}
		results[i] = ValType(b)
	}
	return FuncType{Params: params, Results: results}, nil
}

func readLimits(r byteReader) (Limits, error) {
	flags, err := r.ReadByte()
	if err != nil {
		return Limits{}, err
	}
	min, err := readU64(r)
	if err != nil {
		return Limits{}, err
	}
	lim := Limits{Min: min}
	if flags&0x01 != 0 {
		max, err := readU64(r)
		if err != nil {
			return Limits{}, err
		}
		lim.Max = max
		lim.HasMax = true
	}
	return lim, nil
}

func parseImportSection(m *Module, r byteReader) error {
	n, err := readU32(r)
	if err != nil {
		return err
	}
	if n > maxVectorLen {
		return fmt.Errorf("import section: count %d exceeds %d-element cap", n, maxVectorLen)
	}
	m.Imports = make([]Import, n)
	for i := uint32(0); i < n; i++ {
		mod, err := readName(r)
		if err != nil {
			return fmt.Errorf("import[%d] module: %w", i, err)
		}
		name, err := readName(r)
		if err != nil {
			return fmt.Errorf("import[%d] name: %w", i, err)
		}
		kind, err := r.ReadByte()
		if err != nil {
			return err
		}
		imp := Import{Module: mod, Name: name, Kind: ImportKind(kind)}
		switch ImportKind(kind) {
		case ImportFunc:
			imp.TypeIdx, err = readU32(r)
			if err != nil {
				return err
			}
		case ImportTable:
			et, err := r.ReadByte()
			if err != nil {
				return err
			}
			lim, err := readLimits(r)
			if err != nil {
				return err
			}
			imp.Table = TableType{ElemType: ValType(et), Limits: lim}
		case ImportMemory:
			lim, err := readLimits(r)
			if err != nil {
				return err
			}
			imp.Memory = MemoryType{Limits: lim}
		case ImportGlobal:
			vt, err := r.ReadByte()
			if err != nil {
				return err
			}
			mut, err := r.ReadByte()
			if err != nil {
				return err
			}
			imp.Global = GlobalType{Type: ValType(vt), Mutable: mut == 1}
		default:
			return fmt.Errorf("import[%d]: unknown kind 0x%02x", i, kind)
		}
		m.Imports[i] = imp
	}
	return nil
}

func parseFunctionSection(m *Module, r byteReader) error {
	n, err := readU32(r)
	if err != nil {
		return err
	}
	if n > maxVectorLen {
		return fmt.Errorf("function section: count %d exceeds %d-element cap", n, maxVectorLen)
	}
	m.Functions = make([]Function, n)
	for i := uint32(0); i < n; i++ {
		ti, err := readU32(r)
		if err != nil {
			return err
		}
		m.Functions[i].TypeIdx = ti
	}
	return nil
}

func parseTableSection(m *Module, r byteReader) error {
	n, err := readU32(r)
	if err != nil {
		return err
	}
	if n > maxVectorLen {
		return fmt.Errorf("table section: count %d exceeds %d-element cap", n, maxVectorLen)
	}
	m.Tables = make([]TableType, n)
	for i := uint32(0); i < n; i++ {
		et, err := r.ReadByte()
		if err != nil {
			return err
		}
		lim, err := readLimits(r)
		if err != nil {
			return err
		}
		m.Tables[i] = TableType{ElemType: ValType(et), Limits: lim}
	}
	return nil
}

func parseMemorySection(m *Module, r byteReader) error {
	n, err := readU32(r)
	if err != nil {
		return err
	}
	if n > maxVectorLen {
		return fmt.Errorf("memory section: count %d exceeds %d-element cap", n, maxVectorLen)
	}
	m.Memories = make([]MemoryType, n)
	for i := uint32(0); i < n; i++ {
		lim, err := readLimits(r)
		if err != nil {
			return err
		}
		m.Memories[i] = MemoryType{Limits: lim}
	}
	return nil
}

func parseGlobalSection(m *Module, r byteReader) error {
	n, err := readU32(r)
	if err != nil {
		return err
	}
	if n > maxVectorLen {
		return fmt.Errorf("global section: count %d exceeds %d-element cap", n, maxVectorLen)
	}
	m.Globals = make([]Global, n)
	for i := uint32(0); i < n; i++ {
		vt, err := r.ReadByte()
		if err != nil {
			return err
		}
		mut, err := r.ReadByte()
		if err != nil {
			return err
		}
		expr, err := readConstExpr(r)
		if err != nil {
			return fmt.Errorf("global[%d] init: %w", i, err)
		}
		m.Globals[i] = Global{
			Type: GlobalType{Type: ValType(vt), Mutable: mut == 1},
			Init: expr,
		}
	}
	return nil
}

func parseExportSection(m *Module, r byteReader) error {
	n, err := readU32(r)
	if err != nil {
		return err
	}
	if n > maxVectorLen {
		return fmt.Errorf("export section: count %d exceeds %d-element cap", n, maxVectorLen)
	}
	m.Exports = make([]Export, n)
	for i := uint32(0); i < n; i++ {
		name, err := readName(r)
		if err != nil {
			return err
		}
		kind, err := r.ReadByte()
		if err != nil {
			return err
		}
		idx, err := readU32(r)
		if err != nil {
			return err
		}
		m.Exports[i] = Export{Name: name, Kind: ExportKind(kind), Index: idx}
	}
	return nil
}

func parseElementSection(m *Module, r byteReader) error {
	n, err := readU32(r)
	if err != nil {
		return err
	}
	if n > maxVectorLen {
		return fmt.Errorf("element section: count %d exceeds %d-element cap", n, maxVectorLen)
	}
	m.Elements = make([]ElementSegment, 0, n)
	for i := uint32(0); i < n; i++ {
		flag, err := readU32(r)
		if err != nil {
			return err
		}
		switch flag {
		case 0x00:
			// active, table 0, offset, vec(funcidx)
			off, err := readConstExpr(r)
			if err != nil {
				return fmt.Errorf("element[%d] offset: %w", i, err)
			}
			cnt, err := readU32(r)
			if err != nil {
				return err
			}
			if cnt > maxVectorLen {
				return fmt.Errorf("element[%d]: count %d exceeds %d-byte cap", i, cnt, maxVectorLen)
			}
			idxs := make([]uint32, cnt)
			for j := range idxs {
				v, err := readU32(r)
				if err != nil {
					return err
				}
				idxs[j] = v
			}
			m.Elements = append(m.Elements, ElementSegment{
				TableIdx: 0,
				Offset:   off,
				FuncIdxs: idxs,
			})
		case 0x02:
			// active, tableidx, offset, elemkind, vec(funcidx)
			tIdx, err := readU32(r)
			if err != nil {
				return err
			}
			off, err := readConstExpr(r)
			if err != nil {
				return err
			}
			elemKind, err := r.ReadByte()
			if err != nil {
				return err
			}
			if elemKind != 0x00 {
				return fmt.Errorf("element[%d]: unsupported elemkind 0x%02x", i, elemKind)
			}
			cnt, err := readU32(r)
			if err != nil {
				return err
			}
			if cnt > maxVectorLen {
				return fmt.Errorf("element[%d]: count %d exceeds %d-byte cap", i, cnt, maxVectorLen)
			}
			idxs := make([]uint32, cnt)
			for j := range idxs {
				v, err := readU32(r)
				if err != nil {
					return err
				}
				idxs[j] = v
			}
			m.Elements = append(m.Elements, ElementSegment{
				TableIdx: tIdx,
				Offset:   off,
				FuncIdxs: idxs,
			})
		default:
			return fmt.Errorf("element[%d]: unsupported flag 0x%02x", i, flag)
		}
	}
	return nil
}

func parseCodeSection(m *Module, r byteReader) error {
	n, err := readU32(r)
	if err != nil {
		return err
	}
	if int(n) != len(m.Functions) {
		return fmt.Errorf("code section count %d != function section count %d", n, len(m.Functions))
	}
	for i := uint32(0); i < n; i++ {
		size, err := readU32(r)
		if err != nil {
			return err
		}
		if size > maxFunctionBody {
			return fmt.Errorf("code[%d]: body size %d exceeds %d-byte cap", i, size, maxFunctionBody)
		}
		body := make([]byte, size)
		if _, err := io.ReadFull(r, body); err != nil {
			return fmt.Errorf("code[%d]: %w", i, err)
		}
		m.Functions[i].Body = body
	}
	return nil
}

func parseDataSection(m *Module, r byteReader) error {
	n, err := readU32(r)
	if err != nil {
		return err
	}
	if n > maxVectorLen {
		return fmt.Errorf("data section: count %d exceeds %d-element cap", n, maxVectorLen)
	}
	m.Datas = make([]DataSegment, 0, n)
	for i := uint32(0); i < n; i++ {
		flag, err := readU32(r)
		if err != nil {
			return err
		}
		switch flag {
		case 0x00:
			// active, mem 0, offset, vec(byte)
			off, err := readConstExpr(r)
			if err != nil {
				return err
			}
			b, err := readByteVec(r)
			if err != nil {
				return err
			}
			m.Datas = append(m.Datas, DataSegment{MemIdx: 0, Offset: off, Bytes: b})
		case 0x02:
			// active, memidx, offset, vec(byte)
			mi, err := readU32(r)
			if err != nil {
				return err
			}
			off, err := readConstExpr(r)
			if err != nil {
				return err
			}
			b, err := readByteVec(r)
			if err != nil {
				return err
			}
			m.Datas = append(m.Datas, DataSegment{MemIdx: mi, Offset: off, Bytes: b})
		default:
			return fmt.Errorf("data[%d]: unsupported flag 0x%02x", i, flag)
		}
	}
	return nil
}

// readConstExpr reads one wasm constant expression (single instruction
// followed by 0x0b end). Returns the raw bytes including the 0x0b.
func readConstExpr(r byteReader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		op, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		buf.WriteByte(op)
		if op == 0x0b {
			return buf.Bytes(), nil
		}
		// Decode the immediate(s) for this opcode. Const exprs in MVP are
		// limited to a small handful.
		switch op {
		case 0x41: // i32.const
			v, err := readS32(r)
			if err != nil {
				return nil, err
			}
			writeSLEB(&buf, int64(v))
		case 0x42: // i64.const
			v, err := readS64(r)
			if err != nil {
				return nil, err
			}
			writeSLEB(&buf, v)
		case 0x43: // f32.const
			var b [4]byte
			if _, err := io.ReadFull(r, b[:]); err != nil {
				return nil, err
			}
			buf.Write(b[:])
		case 0x44: // f64.const
			var b [8]byte
			if _, err := io.ReadFull(r, b[:]); err != nil {
				return nil, err
			}
			buf.Write(b[:])
		case 0x23: // global.get
			v, err := readU32(r)
			if err != nil {
				return nil, err
			}
			writeULEB(&buf, uint64(v))
		case 0xd0: // ref.null t
			t, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			buf.WriteByte(t)
		case 0xd2: // ref.func x
			v, err := readU32(r)
			if err != nil {
				return nil, err
			}
			writeULEB(&buf, uint64(v))
		default:
			return nil, fmt.Errorf("const expr: unsupported opcode 0x%02x", op)
		}
	}
}

func writeULEB(buf *bytes.Buffer, v uint64) {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		buf.WriteByte(b)
		if v == 0 {
			return
		}
	}
}

func writeSLEB(buf *bytes.Buffer, v int64) {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		// stop when the remaining bits and the sign bit of the byte agree.
		if (v == 0 && b&0x40 == 0) || (v == -1 && b&0x40 != 0) {
			buf.WriteByte(b)
			return
		}
		buf.WriteByte(b | 0x80)
	}
}

// readerAt wraps a Reader into both an io.Reader and io.ByteReader.
type readerAt struct {
	r interface {
		io.Reader
		io.ByteReader
	}
}

func (a *readerAt) Read(p []byte) (int, error) { return a.r.Read(p) }
func (a *readerAt) ReadByte() (byte, error)    { return a.r.ReadByte() }
