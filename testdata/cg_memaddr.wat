;; Regression fixture for the FoldMemAddend pass: memory accesses whose
;; base is `runtime index + LARGE constant addend`. Without the fold the
;; addend reaches the emitter inside the base expression, bypasses the
;; _consts-table guard, and gc's ARM64 backend folds it into a load/store
;; addressing immediate — which fails to assemble inside very large
;; functions ("LDPSW 27325896(R2): constant is not in pool"). The fold
;; moves the addend into the access's static offset, where the guard
;; routes it through _consts.
;;
;; read_neg exercises a large-magnitude NEGATIVE addend (sign-extends
;; into the same out-of-range immediate); its folded offset holds the
;; uint32 bit pattern and relies on the emitter's mod-2^32 wrap.
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
