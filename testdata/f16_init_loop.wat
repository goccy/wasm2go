;; Runtime f16-table initialization idiom: a loop streaming
;; constant-strided stores from a constant base, covering the full
;; 65536-entry x 4-byte range. The value computation is irrelevant to
;; the detection (real modules vectorize a bit-manipulation convert);
;; only the pointer/counter recurrences and the store coverage matter.
(module
  (memory 5)
  (func $init_full
    (local $p i32) (local $q i32)
    (local.set $p (i32.const 4096))
    (local.set $q (i32.const -65536))
    (loop $L
      (f32.store (local.get $p) (f32.const 1))
      (local.set $p (i32.add (local.get $p) (i32.const 4)))
      (local.set $q (i32.add (local.get $q) (i32.const 1)))
      (br_if $L (i32.ne (local.get $q) (i32.const 0)))
    )
  )
  (func $init_half
    (local $p i32) (local $q i32)
    (local.set $p (i32.const 266240))
    (local.set $q (i32.const -32768))
    (loop $L
      (f32.store (local.get $p) (f32.const 1))
      (local.set $p (i32.add (local.get $p) (i32.const 4)))
      (local.set $q (i32.add (local.get $q) (i32.const 1)))
      (br_if $L (i32.ne (local.get $q) (i32.const 0)))
    )
  )
)
