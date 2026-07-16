;; Passive data segments + memory.init/data.drop — the shape LLVM emits for
;; shared-memory builds (all data passive, initialized once from a start
;; function). exports check both the init'd bytes and post-drop trapping.
(module
  (memory 1 4 shared)
  (data $hello "Hello")
  (data $world ", world")
  (func $init
    (memory.init $hello (i32.const 16) (i32.const 0) (i32.const 5))
    (memory.init $world (i32.const 21) (i32.const 0) (i32.const 7))
    (data.drop $hello))
  (start $init)
  (func (export "read_at") (param i32) (result i32)
    (i32.load8_u (local.get 0)))
  (func (export "reinit_dropped")
    ;; memory.init on a dropped segment with n > 0 must trap
    (memory.init $hello (i32.const 64) (i32.const 0) (i32.const 1)))
  (func (export "reinit_zero_len")
    ;; n == 0 on a dropped segment is allowed by the spec
    (memory.init $hello (i32.const 64) (i32.const 0) (i32.const 0))))
