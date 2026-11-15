;; Memory accesses whose base is `runtime index + LARGE constant addend`.
;; gc's ARM64 backend once folded such an addend into a load/store
;; addressing immediate, which fails to assemble inside very large
;; functions ("LDPSW 27325896(R2): constant is not in pool"). The emitter
;; zero-extends the i32 address before it adds the static offset, so the
;; addend stays in the 32-bit address arithmetic and never reaches an
;; addressing immediate.
;;
;; read_neg exercises a large-magnitude NEGATIVE addend, whose i32 add
;; wraps mod 2^32 as wasm's does.
(module
  (memory (export "memory") 2)
  (func (export "write_far") (param i32 i32)
    (i32.store offset=8
      (i32.add (local.get 0) (i32.const 100000))
      (local.get 1)))
  (func (export "read_far") (param i32) (result i32)
    (i32.load offset=8
      (i32.add (local.get 0) (i32.const 100000))))
  (func (export "read_neg") (param i32) (result i32)
    (i32.load offset=4
      (i32.add (local.get 0) (i32.const -65536)))))
