;; cg_indirect.wat — call_indirect over several distinct function-type
;; signatures (different arity, i32/i64 mixes), plus direct calls to
;; imported and local functions, exercising opCall / opCallIndirect.
(module
  (type $unary    (func (param i32) (result i32)))
  (type $binary   (func (param i32 i32) (result i32)))
  (type $i64bin   (func (param i64 i64) (result i64)))
  (type $noargs   (func (result i32)))
  (type $voidproc (func (param i32)))

  (table 12 funcref)
  (global $sink (mut i32) (i32.const 0))

  (func $negate (type $unary) (i32.sub (i32.const 0) (local.get 0)))
  (func $dbl    (type $unary) (i32.mul (local.get 0) (i32.const 2)))
  (func $addp   (type $binary) (i32.add (local.get 0) (local.get 1)))
  (func $subp   (type $binary) (i32.sub (local.get 0) (local.get 1)))
  (func $mul64  (type $i64bin) (i64.mul (local.get 0) (local.get 1)))
  (func $const7 (type $noargs) (i32.const 7))
  (func $store  (type $voidproc) (global.set $sink (local.get 0)))

  (elem (i32.const 0) $negate $dbl $addp $subp $mul64 $const7 $store)

  (func (export "ind_unary") (param $which i32) (param $x i32) (result i32)
    (call_indirect (type $unary) (local.get $x) (local.get $which)))

  (func (export "ind_binary") (param $which i32) (param $a i32) (param $b i32) (result i32)
    (call_indirect (type $binary) (local.get $a) (local.get $b) (local.get $which)))

  (func (export "ind_i64") (param $which i32) (param $a i64) (param $b i64) (result i64)
    (call_indirect (type $i64bin) (local.get $a) (local.get $b) (local.get $which)))

  (func (export "ind_noargs") (param $which i32) (result i32)
    (call_indirect (type $noargs) (local.get $which)))

  (func (export "ind_void") (param $which i32) (param $v i32) (result i32)
    (call_indirect (type $voidproc) (local.get $v) (local.get $which))
    (global.get $sink))

  ;; direct calls — chains through several locals
  (func (export "direct_chain") (param $x i32) (result i32)
    (call $dbl (call $addp (call $negate (local.get $x)) (i32.const 100))))
)
