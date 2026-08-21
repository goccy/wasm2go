;; cg_mem64_atomics_unshared.wat — threads-proposal atomics on a PLAIN
;; (unshared) memory64, which is legal wasm: the transpiler used to reject
;; every 0xFE opcode under memory64, so this locks the regression. A
;; zero-timeout wait on an unshared memory returns not-equal semantics per
;; the runtime's single-agent handling (never parks).
(module
  (memory i64 1)
  (func (export "bump") (result i32)
    (i32.atomic.store (i64.const 16) (i32.const 40))
    (drop (i32.atomic.rmw.add (i64.const 16) (i32.const 2)))
    (i32.atomic.load (i64.const 16)))
  (func (export "wait_unshared") (result i32)
    (i32.atomic.store (i64.const 32) (i32.const 1))
    (memory.atomic.wait32 (i64.const 32) (i32.const 1) (i64.const 0))))
