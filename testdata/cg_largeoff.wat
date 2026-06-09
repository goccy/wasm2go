;; Trigger codegen's _consts table by using a memory offset >= 4096.
;; Pure-Go emit routes large-offset stores/loads through `_consts[N]`.
(module
  (memory (export "memory") 1)
  (func (export "read_at_8192") (result i32)
    (i32.load offset=8192 (i32.const 0)))
  (func (export "write_at_8192") (param i32)
    (i32.store offset=8192 (i32.const 0) (local.get 0))))
