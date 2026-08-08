;; memory64 with no declared maximum: the >4GiB growth fixture.
(module
  (memory i64 2)
  (func (export "grow") (param i64) (result i64) (memory.grow (local.get 0)))
  (func (export "rw") (param i64 i64) (result i64)
    (i64.store (local.get 0) (local.get 1))
    (i64.load (local.get 0))))
