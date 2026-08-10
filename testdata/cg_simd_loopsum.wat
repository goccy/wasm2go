;; SIMD accumulation loop with scalar loop carries (pointer, counter)
;; — the register-coalesce-across-splices shape. Self-contained: the
;; function seeds linear memory with a deterministic integer pattern,
;; then sums v128 rows into an accumulator and folds the lanes to one
;; i32, so a driver needs no memory access of its own and integer ops
;; keep the result exact.
(module
  (memory (export "memory") 1)
  (func (export "loopsum") (param $n i32) (result i32)
    (local $i i32)
    (local $p i32)
    (local $acc v128)
    ;; Seed: mem[4*i] = i*40503 + 17 for i in [0, 256).
    (local.set $i (i32.const 0))
    (block $done
      (loop $seed
        (br_if $done (i32.ge_u (local.get $i) (i32.const 256)))
        (i32.store (i32.mul (local.get $i) (i32.const 4))
                   (i32.add (i32.mul (local.get $i) (i32.const 40503))
                            (i32.const 17)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $seed)))
    ;; Sum n rows of 16 bytes.
    (local.set $acc (v128.const i32x4 0 0 0 0))
    (local.set $p (i32.const 0))
    (block $out
      (loop $l
        (br_if $out (i32.eqz (local.get $n)))
        (local.set $acc (i32x4.add (local.get $acc) (v128.load (local.get $p))))
        (local.set $p (i32.add (local.get $p) (i32.const 16)))
        (local.set $n (i32.sub (local.get $n) (i32.const 1)))
        (br $l)))
    ;; Fold the four lanes.
    (i32.add
      (i32.add (i32x4.extract_lane 0 (local.get $acc))
               (i32x4.extract_lane 1 (local.get $acc)))
      (i32.add (i32x4.extract_lane 2 (local.get $acc))
               (i32x4.extract_lane 3 (local.get $acc)))))
)
