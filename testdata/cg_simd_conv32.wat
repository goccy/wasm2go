;; Conversion-loop shape (ggml's fp32 row scale): per iteration a
;; v128 load, a load32_splat scale, mul, add, store — with VARIABLE
;; stride bumps on both pointers, the shape the un-unrolled hot
;; loops carry. Window fusion must fold the loads into the region on
;; both pointer widths.
(module
  (memory (export "memory") 1)
  (func (export "conv") (param $p i32) (param $q i32) (param $s i32) (param $n i32)
    (local $acc v128)
    (local.set $acc (v128.const i32x4 0 0 0 0))
    (block $out
      (loop $l
        (br_if $out (i32.eqz (local.get $n)))
        (local.set $acc
          (f32x4.add (local.get $acc)
            (f32x4.mul (v128.load (local.get $p))
                       (v128.load32_splat (local.get $q)))))
        (v128.store (local.get $p) (local.get $acc))
        (local.set $p (i32.add (local.get $p) (local.get $s)))
        (local.set $q (i32.add (local.get $q) (i32.const 4)))
        (local.set $n (i32.sub (local.get $n) (i32.const 1)))
        (br $l)))))
