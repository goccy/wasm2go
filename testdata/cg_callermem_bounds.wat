;; A wasm32 module for the bounds of a memory the caller hands the
;; constructor (NewWithMemory) on an allocation longer than the memory.
;;
;; random fills a buffer with random_get, which refuses one that reaches
;; past the memory with EFAULT; grow is memory.grow.
(module
  (import "wasi_snapshot_preview1" "random_get"
    (func $random_get (param i32 i32) (result i32)))

  (memory 2)

  (func (export "random") (param i32) (param i32) (result i32)
    local.get 0
    local.get 1
    call $random_get)

  (func (export "grow") (param i32) (result i32)
    local.get 0
    memory.grow))
