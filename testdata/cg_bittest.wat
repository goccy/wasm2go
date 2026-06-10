;; Trigger bit-test fusion (BTL+JCC on amd64, TBZ/TBNZ on
;; arm64) by branching on `(x & 1<<bit) != 0`.
(module
  (func (export "bit0_set") (param $x i32) (result i32)
    (if (result i32)
      (i32.and (local.get $x) (i32.const 1))
      (then (i32.const 1))
      (else (i32.const 0))))
  (func (export "bit3_clear") (param $x i32) (result i32)
    (if (result i32)
      (i32.eqz (i32.and (local.get $x) (i32.const 8)))
      (then (i32.const 100))
      (else (i32.const 200))))
  (func (export "bit32_set_i64") (param $x i64) (result i32)
    (if (result i32)
      (i64.ne (i64.and (local.get $x) (i64.const 0x100000000)) (i64.const 0))
      (then (i32.const 1))
      (else (i32.const 0)))))
