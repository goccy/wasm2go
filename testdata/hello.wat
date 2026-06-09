;; hello.wat — minimal wasi_snapshot_preview1 fd_write smoke test.
;;
;; Exports `say_hello`: writes "hello from wasi\n" to fd 1 (stdout).
;; Used by wasm2go to verify the native wasip1 codegen.
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 1)

  ;; "hello from wasi\n" — 16 bytes — at memory offset 16.
  (data (i32.const 16) "hello from wasi\n")

  ;; iovec at offset 0:
  ;;   [0..4)  = buf pointer = 16
  ;;   [4..8)  = buf length  = 16
  (data (i32.const 0) "\10\00\00\00")  ;; little-endian 16
  (data (i32.const 4) "\10\00\00\00")  ;; little-endian 16

  (func (export "say_hello") (result i32)
    (call $fd_write
      (i32.const 1)    ;; fd = 1 (stdout)
      (i32.const 0)    ;; iovs pointer
      (i32.const 1)    ;; iovs length (1 entry)
      (i32.const 32))) ;; nwritten output pointer
)
