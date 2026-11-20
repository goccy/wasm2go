;; cg_wasip1_posix.wat — imports functions of both modules of the Go-native
;; wasi runtime: wasi_snapshot_preview1's fd_write and fd_read, and
;; wasip1_posix_extension's pipe and fd_dup. The pipe made through
;; wasip1_posix_extension is written and read through wasi_snapshot_preview1, so the
;; two modules have to be served by one WasiStubs with one fd table.
;; roundtrip leaves the bytes read at 300 and returns their count, or a
;; negative step number when a call fails.
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasip1_posix_extension" "pipe"
    (func $pipe (param i32) (result i32)))
  (import "wasip1_posix_extension" "fd_dup"
    (func $fd_dup (param i32 i32) (result i32)))

  (memory (export "memory") 1)
  (data (i32.const 200) "posix")

  (func (export "roundtrip") (result i32)
    ;; pipe fds at 100 (read end) and 104 (write end)
    (if (i32.ne (call $pipe (i32.const 100)) (i32.const 0))
      (then (return (i32.const -1))))
    ;; dup the write end; the dup lands at 108
    (if (i32.ne (call $fd_dup (i32.load (i32.const 104)) (i32.const 108)) (i32.const 0))
      (then (return (i32.const -2))))
    ;; iovec at 120: the 5 bytes at 200, written through the dup
    (i32.store (i32.const 120) (i32.const 200))
    (i32.store (i32.const 124) (i32.const 5))
    (if (i32.ne (call $fd_write (i32.load (i32.const 108)) (i32.const 120) (i32.const 1) (i32.const 128)) (i32.const 0))
      (then (return (i32.const -3))))
    ;; iovec at 140: 16 bytes at 300, read from the read end
    (i32.store (i32.const 140) (i32.const 300))
    (i32.store (i32.const 144) (i32.const 16))
    (if (i32.ne (call $fd_read (i32.load (i32.const 100)) (i32.const 140) (i32.const 1) (i32.const 148)) (i32.const 0))
      (then (return (i32.const -4))))
    (i32.load (i32.const 148)))
)
