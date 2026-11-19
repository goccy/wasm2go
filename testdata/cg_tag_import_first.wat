;; cg_tag_import_first.wat — the first import is a tag (as a module linked
;; against wasi-sdk's libc++ imports env.__cpp_exception), the function
;; imports come after it. A call names a function import by its index among
;; the function imports, which is not its index among all the imports, so
;; the translation has to bind each call to the right one: fd_close with one
;; argument, clock_time_get with three.
(module
  (import "env" "__cpp_exception" (tag $exc (param i32)))
  (import "wasi_snapshot_preview1" "fd_close"
    (func $fd_close (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "clock_time_get"
    (func $clock_time_get (param i32 i64 i32) (result i32)))

  (memory (export "memory") 1)

  ;; closing a descriptor that is not open is EBADF (8)
  (func (export "closebad") (result i32)
    (call $fd_close (i32.const 99)))

  ;; the monotonic clock (1) reads, writing its value at 64: errno 0
  (func (export "clock") (result i32)
    (call $clock_time_get (i32.const 1) (i64.const 1) (i32.const 64)))
)
