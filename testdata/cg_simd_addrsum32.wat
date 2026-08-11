;; Variable+variable addressing: the load/splat/store addresses are
;; runtime sums with NO constant side (base+stride computed inline),
;; the shape LP64 clang emits for strided conversion loops. Window
;; fusion must chase these into scalar-node address chains instead of
;; burning one int slot per distinct expression.
(module
  (memory (export "memory") 1)
  (func (export "scale") (param $p i32) (param $q i32) (param $s i32)
    (v128.store (i32.add (local.get $p) (local.get $s))
      (f32x4.mul
        (v128.load (i32.add (local.get $p) (local.get $s)))
        (v128.load32_splat (i32.add (local.get $q) (local.get $s)))))
    (v128.store offset=16 (i32.add (local.get $p) (local.get $s))
      (f32x4.mul
        (v128.load offset=16 (i32.add (local.get $p) (local.get $s)))
        (v128.load32_splat (i32.add (local.get $q) (local.get $s)))))))
