;; cg_brtable_bool.wat — br_table whose selector is a comparison result.
;; wasm comparisons leave i32 0/1 on the stack, so this is valid wasm, but
;; wasm2go's SSA types comparisons as bool; the BrTable verifier must accept
;; that (emitters always materialize bool values via b2i32, i.e. as i32).
;; Shape found in SpiderMonkey's with-Intl build (Fn7964).
(module
  (func (export "pick") (param i32) (result i32)
    (block $b2
      (block $b1
        (block $b0
          (br_table $b0 $b1 $b2 (i32.ge_u (local.get 0) (i32.const 5))))
        (return (i32.const 10)))
      (return (i32.const 20)))
    (i32.const 30)))
