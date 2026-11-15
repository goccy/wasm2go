;; A memory64 memory with no declared maximum, for the fault-to-trap tests
;; (TestMemoryFaultsTrap): loads and stores at run-time addresses, and
;; memory.grow.
(module
  (memory (export "memory") i64 1)
  (func (export "load8") (param i64) (result i32)
    (i32.load8_u (local.get 0)))
  (func (export "load64") (param i64) (result i64)
    (i64.load (local.get 0)))
  (func (export "store64") (param i64 i64)
    (i64.store (local.get 0) (local.get 1)))
  (func (export "size") (result i64) (memory.size))
  (func (export "grow") (param i64) (result i64) (memory.grow (local.get 0))))
