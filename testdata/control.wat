(module
  ;; Iterative factorial.
  (func (export "fact") (param $n i32) (result i32)
    (local $r i32) (local $i i32)
    (local.set $r (i32.const 1))
    (local.set $i (local.get $n))
    (block $exit
      (loop $loop
        (br_if $exit (i32.eqz (local.get $i)))
        (local.set $r (i32.mul (local.get $r) (local.get $i)))
        (local.set $i (i32.sub (local.get $i) (i32.const 1)))
        (br $loop)))
    (local.get $r))

  ;; gcd via Euclid.
  (func (export "gcd") (param $a i32) (param $b i32) (result i32)
    (block $exit
      (loop $loop
        (br_if $exit (i32.eqz (local.get $b)))
        (local.set $a (i32.rem_u (local.get $a) (local.get $b)))
        ;; swap a and b
        (local.get $a)
        (local.get $b)
        (local.set $a)
        (local.set $b)
        (br $loop)))
    (local.get $a))

  ;; if-else returning a value.
  (func (export "max") (param i32 i32) (result i32)
    (if (result i32) (i32.gt_s (local.get 0) (local.get 1))
      (then (local.get 0))
      (else (local.get 1))))

  ;; br_table dispatch.
  (func (export "switch3") (param $i i32) (result i32)
    (block $d
      (block $c
        (block $b
          (block $a
            (br_table $a $b $c $d (local.get $i)))
          (return (i32.const 100)))
        (return (i32.const 200)))
      (return (i32.const 300)))
    (i32.const 999)))
