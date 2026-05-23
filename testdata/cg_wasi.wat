;; cg_wasi.wat — imports several wasi_snapshot_preview1 functions so the
;; NativeWASI codegen path (wasip1_native.go) emits a full Go-native impl.
;; say_hello writes a fixed string to stdout; clock_now reads the monotonic
;; clock; rand_byte pulls one random byte. Exercised end-to-end with the
;; generated DefaultWASI backend.
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "clock_time_get"
    (func $clock_time_get (param i32 i64 i32) (result i32)))
  (import "wasi_snapshot_preview1" "random_get"
    (func $random_get (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "args_sizes_get"
    (func $args_sizes_get (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "environ_sizes_get"
    (func $environ_sizes_get (param i32 i32) (result i32)))

  (memory (export "memory") 1)

  (data (i32.const 16) "wasi native ok\n")
  (data (i32.const 0) "\10\00\00\00")
  (data (i32.const 4) "\0f\00\00\00")

  (func (export "say_hello") (result i32)
    (call $fd_write
      (i32.const 1)
      (i32.const 0)
      (i32.const 1)
      (i32.const 64)))

  (func (export "clock_now") (result i32)
    (call $clock_time_get (i32.const 1) (i64.const 0) (i32.const 80)))

  (func (export "rand_byte") (result i32)
    (drop (call $random_get (i32.const 96) (i32.const 1)))
    (i32.load8_u (i32.const 96)))

  (func (export "arg_count") (result i32)
    (drop (call $args_sizes_get (i32.const 100) (i32.const 104)))
    (i32.load (i32.const 100)))

  (func (export "env_count") (result i32)
    (drop (call $environ_sizes_get (i32.const 108) (i32.const 112)))
    (i32.load (i32.const 108)))
)
