;; cg_callermem_bounds.wat for a memory64 module: the same exports, with
;; the memory64's i64 addresses, sizes and page counts.
(module
  (import "wasi_snapshot_preview1" "random_get"
    (func $random_get (param i64 i64) (result i32)))

  (memory i64 2)

  (func (export "load") (param i64) (result i32)
    i64.const 0
    local.get 0
    i64.const 1
    memory.copy
    i64.const 0
    i32.load8_u)

  (func (export "store") (param i64) (param i32)
    local.get 0
    local.get 1
    i32.store8)

  (func (export "random") (param i64) (param i64) (result i32)
    local.get 0
    local.get 1
    call $random_get)

  (func (export "grow") (param i64) (result i64)
    local.get 0
    memory.grow))
