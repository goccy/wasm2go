;; wexports.wat — exercises bulk-dispatch exports under the
;; `<prefix><svc>_<mt>` naming convention (here the prefix is "w_"),
;; the targets of the InvokeExport switch. Every bulk export has the
;; uniform signature (i32, i32) -> i64.
(module
  (func (export "w_0_0") (param i32 i32) (result i64)
    (i64.extend_i32_s (i32.add (local.get 0) (local.get 1))))
  (func (export "w_0_1") (param i32 i32) (result i64)
    (i64.extend_i32_s (i32.sub (local.get 0) (local.get 1))))
  (func (export "w_1_0") (param i32 i32) (result i64)
    (i64.extend_i32_s (i32.mul (local.get 0) (local.get 1))))
  ;; a non-bulk export — gets its own direct wrapper
  (func (export "helper") (param i32) (result i32)
    (i32.add (local.get 0) (i32.const 1))))
