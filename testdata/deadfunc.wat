;; deadfunc.wat — exercises whole-function reachability.
;;   used    : exported  → a root
;;   helper  : called by `used`  → reachable transitively
;;   tabled  : only in the element segment → reachable (call_indirect)
;;   dead    : not exported, not called, not in the table → UNREACHABLE
(module
  (table 1 funcref)
  (elem (i32.const 0) $tabled)

  (func $used (export "used") (param i32) (result i32)
    (i32.add (local.get 0) (call $helper)))

  (func $helper (result i32)
    (i32.const 42))

  (func $tabled (result i32)
    (i32.const 7))

  (func $dead (param i32) (result i32)
    (i32.mul (local.get 0) (i32.const 99))))
