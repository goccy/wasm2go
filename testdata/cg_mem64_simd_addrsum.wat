;; Variable+variable addressing: the load/splat/store addresses are
;; runtime sums with NO constant side (base+stride computed inline),
;; the shape LP64 clang emits for strided conversion loops. Window
;; fusion must chase these into scalar-node address chains instead of
;; burning one int slot per distinct expression.
(module
  (memory (export "memory") i64 1)
  (func (export "scale") (param $p i64) (param $q i64) (param $s i64)
    (v128.store (i64.add (local.get $p) (local.get $s))
      (f32x4.mul
        (v128.load (i64.add (local.get $p) (local.get $s)))
        (v128.load32_splat (i64.add (local.get $q) (local.get $s)))))
    (v128.store offset=16 (i64.add (local.get $p) (local.get $s))
      (f32x4.mul
        (v128.load offset=16 (i64.add (local.get $p) (local.get $s)))
        (v128.load32_splat (i64.add (local.get $q) (local.get $s)))))))
