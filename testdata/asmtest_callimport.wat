;; asmtest_callimport.wat — minimal fixture for the asmgen OpCallImport
;; differential test. One imported `host.add(i32,i32)->i32` plus three
;; exported wasm functions that exercise different param widths and
;; return-value handling for an asm CALL to the host import wrapper.
(module
  (import "host" "add"  (func $hostadd  (param i32 i32) (result i32)))
  (import "host" "add64" (func $hostadd64 (param i64 i64) (result i64)))
  (import "host" "noop" (func $hostnoop (param i32)))

  ;; call_hostadd(a, b) = host.add(a, b)
  (func (export "call_hostadd") (param i32 i32) (result i32)
    (call $hostadd (local.get 0) (local.get 1)))

  ;; call_hostadd64(a, b) = host.add64(a, b)
  (func (export "call_hostadd64") (param i64 i64) (result i64)
    (call $hostadd64 (local.get 0) (local.get 1)))

  ;; call_hostnoop(x) calls a void-returning host fn and then returns x+1.
  ;; Validates that the asm correctly handles a CallImport whose
  ;; result_type is the Mem sentinel (no readback).
  (func (export "call_hostnoop") (param i32) (result i32)
    (call $hostnoop (local.get 0))
    (i32.add (local.get 0) (i32.const 1)))
)
