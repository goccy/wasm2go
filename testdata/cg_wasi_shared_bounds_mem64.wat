;; cg_wasi_shared_bounds.wat for a shared memory64: the same exports, with
;; the memory64's i64 addresses, sizes and page counts, bound to the *64
;; WASI imports.
(module
  (import "wasi_snapshot_preview1" "random_get"
    (func $random_get (param i64 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_spawn"
    (func $proc_spawn (param i64 i64 i64 i32 i32 i32 i64 i64) (result i32)))

  (memory i64 1 4 shared)

  (func (export "random") (param i64) (param i64) (result i32)
    local.get 0
    local.get 1
    call $random_get)

  (func (export "spawn") (param i64) (result i32)
    local.get 0
    i64.const 0
    i64.const 0
    i32.const -1
    i32.const -1
    i32.const -1
    i64.const 0
    i64.const 16
    call $proc_spawn)

  (func (export "store") (param i64) (param i32)
    local.get 0
    local.get 1
    i32.store8)

  (func (export "grow") (param i64) (result i64)
    local.get 0
    memory.grow))
