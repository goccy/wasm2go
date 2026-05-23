;; cg_frame.wat — the Emscripten C++ stack-frame allocation idiom:
;;   global.set $sp (local.tee $fp (i32.sub (global.get $sp) (i32.const N)))
;; wasm2go recognizes this and emits the compact `lL = subg(&m.gK, N)`
;; rewrite (tryEmitFrameAlloc). Both an i32 stack pointer and the
;; add-of-negative-constant variant are exercised.
(module
  (global $sp (mut i32) (i32.const 65536))
  (global $sp64 (mut i64) (i64.const 1048576))
  (memory 1)

  ;; Classic frame alloc: reserve 32 bytes, return the new frame pointer.
  (func (export "alloc_frame") (result i32)
    (local $fp i32)
    (global.set $sp (local.tee $fp (i32.sub (global.get $sp) (i32.const 32))))
    (local.get $fp))

  ;; Frame alloc via add-of-negative-constant (the i32.add form).
  (func (export "alloc_frame_add") (result i32)
    (local $fp i32)
    (global.set $sp (local.tee $fp (i32.add (global.get $sp) (i32.const -48))))
    (local.get $fp))

  ;; Release the frame back.
  (func (export "free_frame") (param $n i32)
    (global.set $sp (i32.add (global.get $sp) (local.get $n))))

  (func (export "sp_now") (result i32) (global.get $sp))

  ;; i64-global frame alloc (subg64 path).
  (func (export "alloc64") (result i64)
    (local $fp i64)
    (global.set $sp64 (local.tee $fp (i64.sub (global.get $sp64) (i64.const 64))))
    (local.get $fp))
)
