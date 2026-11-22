;; cg_oob.wat — out-of-bounds linear-memory accesses. Each must end in the
;; wasm out-of-bounds trap and never reach memory outside the instance.
;;
;; The bulk exports (w_<svc>_<mt>) go through the generated Inv_<svc>_<mt>
;; entry points, which recover traps into errors; load_at is a direct export,
;; which lets the trap propagate as a panic.
(module
  (memory (export "memory") 1)
  ;; A shared memory image needs at least one data segment.
  (data (i32.const 1024) "oob")

  ;; w_1_0 — i32.load at a runtime address. base + u32 address stays below
  ;; 4 GiB.
  (func (export "w_1_0") (param i32 i32) (result i64)
    (i64.extend_i32_u (i32.load (local.get 0))))

  ;; w_1_1 — i32.store at a runtime address.
  (func (export "w_1_1") (param i32 i32) (result i64)
    (i32.store (local.get 0) (i32.const 7))
    (i64.const 0))

  ;; w_1_2 — constant address plus the largest static offset: the furthest
  ;; any access can reach, just under 8 GiB past the memory base.
  (func (export "w_1_2") (param i32 i32) (result i64)
    (i64.extend_i32_u (i32.load offset=4294967280 (i32.const 4294967280))))

  ;; w_1_3 — memory.grow by l0 pages; returns the previous size in pages.
  (func (export "w_1_3") (param i32 i32) (result i64)
    (i64.extend_i32_s (memory.grow (local.get 0))))

  ;; load_at — the same load as w_1_0 through a direct export.
  (func (export "load_at") (param i32) (result i32)
    (i32.load (local.get 0))))
