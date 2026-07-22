;; Fixture for the eqz→comparison fusion regression tests: i32.eqz and
;; i64.eqz in both branch-control position (must fuse to a direct Go
;; comparison, no helper) and value position (b2i32-materialized 0/1).
(module
  (func (export "branch32") (param $x i32) (result i32)
    (if (result i32) (i32.eqz (local.get $x))
      (then (i32.const 10))
      (else (i32.const 20))))
  (func (export "value32") (param $x i32) (result i32)
    (i32.eqz (local.get $x)))
  (func (export "value64") (param $x i64) (result i32)
    (i64.eqz (local.get $x))))
