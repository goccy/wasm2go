;; cg_bulkmem.wat — exercises the 0xFC-prefixed instruction family:
;; saturating float→int truncation (handleFCOp cases 0-7), memory.copy
;; (case 10) and memory.fill (case 11). Also the non-saturating trunc
;; opcodes and load/store at varied widths.
(module
  (memory (export "memory") 1)
  (data (i32.const 0) "abcdefghij")

  (func (export "trunc_sat_i32_f32_s") (param f32) (result i32)
    (i32.trunc_sat_f32_s (local.get 0)))
  (func (export "trunc_sat_i32_f32_u") (param f32) (result i32)
    (i32.trunc_sat_f32_u (local.get 0)))
  (func (export "trunc_sat_i32_f64_s") (param f64) (result i32)
    (i32.trunc_sat_f64_s (local.get 0)))
  (func (export "trunc_sat_i32_f64_u") (param f64) (result i32)
    (i32.trunc_sat_f64_u (local.get 0)))
  (func (export "trunc_sat_i64_f32_s") (param f32) (result i64)
    (i64.trunc_sat_f32_s (local.get 0)))
  (func (export "trunc_sat_i64_f64_u") (param f64) (result i64)
    (i64.trunc_sat_f64_u (local.get 0)))

  ;; memory.copy: copy n bytes from src to dst, then return dst byte.
  (func (export "mem_copy") (param $dst i32) (param $src i32) (param $n i32) (result i32)
    (memory.copy (local.get $dst) (local.get $src) (local.get $n))
    (i32.load8_u (local.get $dst)))

  ;; memory.fill: set n bytes at addr to value, then return that byte.
  (func (export "mem_fill") (param $addr i32) (param $val i32) (param $n i32) (result i32)
    (memory.fill (local.get $addr) (local.get $val) (local.get $n))
    (i32.load8_u (local.get $addr)))

  ;; widened loads/stores.
  (func (export "load16_s") (param i32) (result i32)
    (i32.load16_s (local.get 0)))
  (func (export "store16") (param i32 i32)
    (i32.store16 (local.get 0) (local.get 1)))
  (func (export "load64") (param i32) (result i64)
    (i64.load (local.get 0)))
)
