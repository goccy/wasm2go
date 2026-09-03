# Assembly overrides

A assembly override lets the project that produced a wasm module supply
the assembly body of one of its exported functions. wasm2go wraps the
body in a fixed ABI, keeps the lowered body as the portable fallback,
and dispatches at runtime on the CPU features the body declares. The
transpiler never learns what the function computes; it only checks that
the manifest describes the module truthfully.

The mechanism exists for one situation: a leaf compute function whose
wasm shape the transpiler cannot yet turn into competitive machine
code. It is not a way to bypass the wasm execution model, and every
override should be paired with the wasm2go issue that would make it
unnecessary. When wasm2go can lower the function well from the wasm,
delete the override.

## What a body may do

The contract keeps a body inside the wasm execution model:

- **Linear memory only, through the prologue's registers.** The body
  receives the memory base and the current memory size (bytes). Every
  access range must be checked against the size before the first load
  or store of that range, and a miss must branch to the `ovr_oob`
  label, which wasm2go appends: it calls the module's out-of-bounds trap
  (the same trap the lowered code raises). Nothing outside
  `[base, base+size)` may be read or written. Stack scratch inside the
  declared frame is fine.
- **No calls.** No host imports, no other module functions, no Go
  runtime symbols. The manifest loader rejects `CALL`/`BL`/`SVC`/
  `SYSCALL` and any `·symbol` reference that is not the body's own
  `·ovr_`-prefixed data.
- **Same meaning as the wasm function.** Under the module's own
  semantics, or under the rounding the project has explicitly accepted
  (fused multiply-add, accumulation order). The project's tests must
  check the override against the lowered body.
- **A leaf with one entry and its own `RET`.** wasm2go writes the
  `TEXT` header and the prologue; the body ends with `RET` (falling off
  the end reaches `ovr_oob`).

## Manifest

```json
{
  "version": 1,
  "memory64": true,
  "functions": [
    {
      "export": "my_dot",
      "params": ["i32", "i64", "i64"],
      "result": "f32",
      "bodies": [
        {"arch": "arm64", "feature": "dotprod", "frame": 16, "file": "my_dot_arm64_dotprod.s"},
        {"arch": "amd64", "feature": "avx2",    "frame": 16, "file": "my_dot_amd64_avx2.s"}
      ]
    }
  ]
}
```

- `memory64` must match the module (it decides the pointer width of
  the arguments).
- `export` must name an exported, module-defined function whose
  signature is exactly `params` / `result` (`result` omitted or `null`
  when there is none). Value types: `i32`, `i64`, `f32`, `f64`.
- `arch` is `arm64` or `amd64`. `feature` is one of, most specific
  first: arm64 `i8mm`, `dotprod`, `neon`; amd64 `avx512vnni`, `avx2`,
  `sse4`. `neon` and `sse4` are the architecture baselines (the same
  baselines the lowered asm assumes: NEON, x86-64-v2). A body listed
  for a feature runs only when the CPU reports it; the baseline body,
  when given, replaces the portable twin entirely; otherwise the
  lowered body remains the fallback.
- `frame` is the body's stack frame in bytes (a multiple of 8).
- `file` is the body, resolved relative to the manifest.

Pass the manifest with `wasm2go -asm-overrides <path>` (or
`Options.AsmOverrides`). The exports it names are kept out of line
by the inliner so every call reaches the replaced body.

## ABI

wasm2go emits, per body:

```
TEXT ·<sym>(SB), $<frame>-<argBytes>
	NO_LOCAL_POINTERS
	<prologue>
	<body>
ovr_oob:
	[VZEROUPPER]           // amd64, non-sse4 bodies
	CALL ·<trap>(SB)
	RET
```

Prologue registers:

| arch  | memory base | memory size (bytes) | module pointer (clobberable) |
|-------|-------------|---------------------|------------------------------|
| arm64 | `R20`       | `R21`               | `R0`                         |
| amd64 | `R14`       | `R15`               | `AX`                         |

Every other register follows Go's ABI0 assembly rules (all caller
saved; on arm64 do not touch `R18`, `R28`, `R29`, `R30`).

Arguments are read from the frame as `l<i>+<offset>(FP)` and the result
written to `r0+<offset>(FP)`. Offsets follow the ABI0 layout: the
module pointer occupies bytes 0..8, then each parameter at its natural
size and alignment (4 for `i32`/`f32`, 8 for `i64`/`f64`), then the
result at the next 8-aligned offset. `argBytes` is the end of the last
value with no trailing padding. For example `(i32, i64, i64) -> f32`
on memory64 is `l0+8`, `l1+16`, `l2+24`, `r0+32`, `argBytes` 36; the
same export on a 32-bit memory is `l0+8`, `l1+12`, `l2+16`, `r0+24`,
`argBytes` 28. Pointer-typed parameters are wasm addresses: add the
memory base after checking the range.

wasm2go cross-checks the rule against the frame size the compiler
derived for the lowered body and fails the transpile on any mismatch,
so a body cannot be wired to a frame it did not expect.

Labels inside the body are function-local; the `kov_` prefix is
reserved for wasm2go. Constant data belongs to the body: `DATA`/`GLOBL`
entries named `·ovr_<something>` in the same file.

## Dispatch

Under the function's own name wasm2go emits a frameless stub that
branches on package-local mirrors of the CPU feature variables — one
predicted branch per declared level, most specific first — and finally
jumps to the baseline: the baseline override body if one is declared,
else the lowered body transformed for the portable instruction set.
Architectures without a body, and the pure-Go build, are untouched.

## Verification the project owes

wasm2go validates structure, not meaning. The project that ships
overrides is responsible for:

- a numeric test of every body against a reference (and against the
  lowered body, so the override never drifts from the wasm), on every
  input length class the function handles (vector body, tails, zero);
- running that test on hardware that has the declared features, or
  skipping the level explicitly when it cannot;
- recording, per override, the wasm2go issue that tracks lowering the
  function from the wasm instead.
