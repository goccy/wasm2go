;; cg_oob64.wat — out-of-bounds accesses to a memory64 linear memory. Each
;; must end in a trap and never reach memory outside the instance, however
;; close to 2^64 the address is.
;;
;; The bulk exports (w_<svc>_<mt>) take the address in l0 and go through the
;; generated Inv_<svc>_<mt> entry points; load_at is a direct export.
(module
  (memory (export "memory") i64 1)
  ;; A shared memory image needs at least one data segment.
  (data (i64.const 1024) "oob")

  ;; w_1_0 — i64.load at a runtime address.
  (func (export "w_1_0") (param i64 i64) (result i64)
    (i64.load (local.get 0)))

  ;; w_1_1 — i64.store at a runtime address.
  (func (export "w_1_1") (param i64 i64) (result i64)
    (i64.store (local.get 0) (i64.const 7))
    (i64.const 0))

  ;; w_1_2 — i32.load with a static offset, which a large address wraps
  ;; past 2^64.
  (func (export "w_1_2") (param i64 i64) (result i64)
    (i64.extend_i32_u (i32.load offset=32 (local.get 0))))

  ;; w_1_3 — memory.grow by l0 pages; returns the previous size in pages.
  (func (export "w_1_3") (param i64 i64) (result i64)
    (memory.grow (local.get 0)))

  ;; w_1_4 — i32.atomic.load at a runtime address.
  (func (export "w_1_4") (param i64 i64) (result i64)
    (i64.extend_i32_u (i32.atomic.load (local.get 0))))

  ;; w_1_5 — a constant address whose sum with the static offset wraps
  ;; past 2^64 to 8.
  (func (export "w_1_5") (param i64 i64) (result i64)
    (i64.load offset=18446744073709551608 (i64.const 16)))

  ;; load_at — the same load as w_1_0 through a direct export.
  (func (export "load_at") (param i64) (result i64)
    (i64.load (local.get 0))))
