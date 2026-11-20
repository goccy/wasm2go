;; A module with a SHARED memory (threads) for the bounds the WASI host puts
;; on guest addresses: the memory's backing array spans its declared
;; maximum from the start, and only memory.size says how much of it the
;; guest may touch.
;;
;; random fills a buffer with random_get, which refuses one past memory.size
;; with EFAULT. spawn starts the command whose path is the C string at its
;; argument with proc_spawn (no argv, no environment, the instance's own
;; streams, the pid written at 16): a path whose NUL is not within the
;; memory is refused with EINVAL. store writes one byte; grow is
;; memory.grow.
(module
  (import "wasi_snapshot_preview1" "random_get"
    (func $random_get (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_spawn"
    (func $proc_spawn (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))

  (memory 1 4 shared)

  (func (export "random") (param i32) (param i32) (result i32)
    local.get 0
    local.get 1
    call $random_get)

  (func (export "spawn") (param i32) (result i32)
    local.get 0
    i32.const 0
    i32.const 0
    i32.const -1
    i32.const -1
    i32.const -1
    i32.const 0
    i32.const 16
    call $proc_spawn)

  (func (export "store") (param i32) (param i32)
    local.get 0
    local.get 1
    i32.store8)

  (func (export "grow") (param i32) (result i32)
    local.get 0
    memory.grow))
