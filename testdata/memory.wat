(module
  (memory (export "memory") 1)

  ;; data segment: write "hi\0" at offset 16.
  (data (i32.const 16) "hi\00")

  (func (export "load_byte") (param $addr i32) (result i32)
    (i32.load8_u (local.get $addr)))

  (func (export "store_byte") (param $addr i32) (param $val i32)
    (i32.store8 (local.get $addr) (local.get $val)))

  (func (export "load_i32") (param $addr i32) (result i32)
    (i32.load (local.get $addr)))

  (func (export "store_i32") (param $addr i32) (param $val i32)
    (i32.store (local.get $addr) (local.get $val)))

  (func (export "sum_bytes") (param $addr i32) (param $n i32) (result i32)
    (local $i i32) (local $s i32)
    (block $exit
      (loop $loop
        (br_if $exit (i32.ge_s (local.get $i) (local.get $n)))
        (local.set $s (i32.add (local.get $s)
          (i32.load8_u (i32.add (local.get $addr) (local.get $i)))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop)))
    (local.get $s))

  ;; Indirect-call dispatch: call table[idx](x).
  (table 4 funcref)
  (func $double (param i32) (result i32) (i32.mul (local.get 0) (i32.const 2)))
  (func $square (param i32) (result i32) (i32.mul (local.get 0) (local.get 0)))
  (func $triple (param i32) (result i32) (i32.mul (local.get 0) (i32.const 3)))
  (elem (i32.const 0) $double $square $triple)

  (type $unop (func (param i32) (result i32)))

  (func (export "dispatch") (param $idx i32) (param $x i32) (result i32)
    (call_indirect (type $unop) (local.get $x) (local.get $idx))))
