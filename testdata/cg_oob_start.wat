;; cg_oob_start.wat — a start section that reads past the linear memory.
;; Constructing the module must panic with the wasm out-of-bounds trap.
(module
  (memory 1)
  (global $g (mut i32) (i32.const 0))
  (func $start
    (global.set $g (i32.load (i32.const 65536))))
  (start $start)
  (func (export "get") (result i32)
    (global.get $g)))
