;; cg_memops.wat — every memory load/store opcode at every width and sign,
;; for both i32 and i64, plus memory.size and memory.grow. Drives the full
;; handleMemoryOp dispatch in the legacy fncompiler and the SSA memory
;; lowering.
(module
  (memory (export "memory") 2)
  (data (i32.const 0) "\01\02\03\04\05\06\07\08\09\0a\0b\0c\0d\0e\0f\10")

  ;; --- i32 loads ---
  (func (export "l_i32") (param i32) (result i32) (i32.load (local.get 0)))
  (func (export "l_i32_8s") (param i32) (result i32) (i32.load8_s (local.get 0)))
  (func (export "l_i32_8u") (param i32) (result i32) (i32.load8_u (local.get 0)))
  (func (export "l_i32_16s") (param i32) (result i32) (i32.load16_s (local.get 0)))
  (func (export "l_i32_16u") (param i32) (result i32) (i32.load16_u (local.get 0)))
  ;; --- i64 loads ---
  (func (export "l_i64") (param i32) (result i64) (i64.load (local.get 0)))
  (func (export "l_i64_8s") (param i32) (result i64) (i64.load8_s (local.get 0)))
  (func (export "l_i64_8u") (param i32) (result i64) (i64.load8_u (local.get 0)))
  (func (export "l_i64_16s") (param i32) (result i64) (i64.load16_s (local.get 0)))
  (func (export "l_i64_16u") (param i32) (result i64) (i64.load16_u (local.get 0)))
  (func (export "l_i64_32s") (param i32) (result i64) (i64.load32_s (local.get 0)))
  (func (export "l_i64_32u") (param i32) (result i64) (i64.load32_u (local.get 0)))
  ;; --- float loads ---
  (func (export "l_f32") (param i32) (result f32) (f32.load (local.get 0)))
  (func (export "l_f64") (param i32) (result f64) (f64.load (local.get 0)))

  ;; --- i32 stores (store then read back) ---
  (func (export "s_i32") (param i32 i32) (result i32)
    (i32.store (local.get 0) (local.get 1))
    (i32.load (local.get 0)))
  (func (export "s_i32_8") (param i32 i32) (result i32)
    (i32.store8 (local.get 0) (local.get 1))
    (i32.load8_u (local.get 0)))
  (func (export "s_i32_16") (param i32 i32) (result i32)
    (i32.store16 (local.get 0) (local.get 1))
    (i32.load16_u (local.get 0)))
  ;; --- i64 stores ---
  (func (export "s_i64") (param i32 i64) (result i64)
    (i64.store (local.get 0) (local.get 1))
    (i64.load (local.get 0)))
  (func (export "s_i64_8") (param i32 i64) (result i64)
    (i64.store8 (local.get 0) (local.get 1))
    (i64.load8_u (local.get 0)))
  (func (export "s_i64_16") (param i32 i64) (result i64)
    (i64.store16 (local.get 0) (local.get 1))
    (i64.load16_u (local.get 0)))
  (func (export "s_i64_32") (param i32 i64) (result i64)
    (i64.store32 (local.get 0) (local.get 1))
    (i64.load32_u (local.get 0)))
  ;; --- float stores ---
  (func (export "s_f32") (param i32 f32) (result f32)
    (f32.store (local.get 0) (local.get 1))
    (f32.load (local.get 0)))
  (func (export "s_f64") (param i32 f64) (result f64)
    (f64.store (local.get 0) (local.get 1))
    (f64.load (local.get 0)))

  ;; --- memory.size / memory.grow ---
  (func (export "mem_size") (result i32) (memory.size))
  (func (export "mem_grow") (param i32) (result i32) (memory.grow (local.get 0)))

  ;; offset-bearing loads/stores: exercise the memarg offset field.
  (func (export "l_offset") (param i32) (result i32)
    (i32.load offset=8 (local.get 0)))
  (func (export "s_offset") (param i32 i32) (result i32)
    (i32.store offset=12 (local.get 0) (local.get 1))
    (i32.load offset=12 (local.get 0)))
)
