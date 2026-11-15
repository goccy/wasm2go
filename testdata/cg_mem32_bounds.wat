;; Bounds of a wasm32 memory (see TestMem32OutOfBoundsTraps): plain loads
;; and stores of every width at and around memory.size, static offsets
;; whose sum with the address passes 4 GiB, constant addresses, a v128
;; access, and the same after memory.grow.
(module
  (memory (export "memory") 1)
  (func (export "load8") (param i32) (result i32)
    (i32.load8_u (local.get 0)))
  (func (export "load16") (param i32) (result i32)
    (i32.load16_u (local.get 0)))
  (func (export "load32") (param i32) (result i32)
    (i32.load (local.get 0)))
  (func (export "load64") (param i32) (result i64)
    (i64.load (local.get 0)))
  (func (export "loadf64") (param i32) (result f64)
    (f64.load (local.get 0)))
  ;; offset 16: the address plus the offset is a 33-bit sum.
  (func (export "load32off") (param i32) (result i32)
    (i32.load offset=16 (local.get 0)))
  ;; an offset just below 4 GiB.
  (func (export "load32far") (param i32) (result i32)
    (i32.load offset=0xfffffff0 (local.get 0)))
  (func (export "store8") (param i32 i32)
    (i32.store8 (local.get 0) (local.get 1)))
  (func (export "store16") (param i32 i32)
    (i32.store16 (local.get 0) (local.get 1)))
  (func (export "store32") (param i32 i32)
    (i32.store (local.get 0) (local.get 1)))
  (func (export "store64") (param i32 i64)
    (i64.store (local.get 0) (local.get 1)))
  (func (export "store64off") (param i32 i64)
    (i64.store offset=16 (local.get 0) (local.get 1)))
  (func (export "constlow") (result i32)
    (i32.load (i32.const 65532)))
  (func (export "consthigh") (result i32)
    (i32.load (i32.const 65536)))
  ;; 0xfffffffc + 8 passes 4 GiB.
  (func (export "constwrap") (result i32)
    (i32.load offset=8 (i32.const 0xfffffffc)))
  ;; two loads off one address: the first one's check may stand for both.
  (func (export "loadpair") (param i32) (result i64)
    (i64.add (i64.load (local.get 0)) (i64.load offset=8 (local.get 0))))
  ;; a store that happens, then a load that may trap.
  (func (export "storethenload") (param i32 i64) (result i64)
    (i64.store (i32.const 0) (local.get 1))
    (i64.load (local.get 0)))
  (func (export "vload") (param i32) (result i32)
    (i32x4.extract_lane 0 (v128.load (local.get 0))))
  (func (export "size") (result i32) (memory.size))
  (func (export "grow") (param i32) (result i32) (memory.grow (local.get 0)))
  ;; grows by a page, then loads: the load sees the new page.
  (func (export "growload") (param i32) (result i32)
    (drop (memory.grow (i32.const 1)))
    (i32.load8_u (local.get 0))))
