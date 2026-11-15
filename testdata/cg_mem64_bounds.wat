;; memory64 bounds: every kind of access at the edges of memory.size —
;; the last bytes that are in bounds, one past them, far past the memory,
;; at 2^63, and at addresses whose sum with the static offset wraps a
;; u64 — before and after memory.grow. The memory starts at its 2-page
;; minimum, so a static offset past 128 KiB takes the check that also
;; compares memory.size with the offset.
(module
  (memory i64 2 8)

  (func (export "load8") (param i64) (result i32) (i32.load8_u (local.get 0)))
  (func (export "load16") (param i64) (result i32) (i32.load16_u (local.get 0)))
  (func (export "load32") (param i64) (result i32) (i32.load (local.get 0)))
  (func (export "load64") (param i64) (result i64) (i64.load (local.get 0)))
  (func (export "loadf64") (param i64) (result f64) (f64.load (local.get 0)))
  (func (export "load64s32") (param i64) (result i64) (i64.load32_s (local.get 0)))
  (func (export "load32off") (param i64) (result i32) (i32.load offset=16 (local.get 0)))
  ;; a static offset of 192 KiB, above the declared minimum
  (func (export "load8far") (param i64) (result i32) (i32.load8_u offset=196608 (local.get 0)))
  ;; a static offset whose sum with the size overflows a u64
  (func (export "load64max") (param i64) (result i64)
    (i64.load offset=18446744073709551615 (local.get 0)))

  (func (export "store8") (param i64 i32) (i32.store8 (local.get 0) (local.get 1)))
  (func (export "store16") (param i64 i32) (i32.store16 (local.get 0) (local.get 1)))
  (func (export "store32") (param i64 i32) (i32.store (local.get 0) (local.get 1)))
  (func (export "store64") (param i64 i64) (i64.store (local.get 0) (local.get 1)))
  (func (export "store64n32") (param i64 i64) (i64.store32 (local.get 0) (local.get 1)))
  (func (export "store64off") (param i64 i64) (i64.store offset=16 (local.get 0) (local.get 1)))

  ;; constant addresses: inside the minimum, past it, and one whose sum
  ;; with the offset wraps
  (func (export "constlow") (result i64) (i64.load (i64.const 8)))
  (func (export "consthigh") (result i32) (i32.load8_u (i64.const 196608)))
  (func (export "constwrap") (result i64) (i64.load offset=16 (i64.const -8)))

  ;; atomics the generator emits inline, and one it leaves to a helper
  (func (export "atomicload64") (param i64) (result i64) (i64.atomic.load (local.get 0)))
  (func (export "atomicstore32") (param i64 i32) (i32.atomic.store (local.get 0) (local.get 1)))
  (func (export "atomicadd32") (param i64 i32) (result i32) (i32.atomic.rmw.add (local.get 0) (local.get 1)))

  (func (export "vload") (param i64) (result i64) (i64x2.extract_lane 0 (v128.load (local.get 0))))
  (func (export "vstore") (param i64 i64) (v128.store (local.get 0) (i64x2.splat (local.get 1))))
  ;; two loads off one address, which share one coalesced range check
  (func (export "vsum") (param i64) (result i64)
    (i64x2.extract_lane 0
      (i64x2.add (v128.load (local.get 0)) (v128.load offset=16 (local.get 0)))))
  ;; loads, an add and a store the generator fuses into one region
  (func (export "vaddstore") (param i64 i64)
    (v128.store (local.get 0)
      (i64x2.add (v128.load (local.get 1)) (v128.load offset=16 (local.get 1)))))

  (func (export "fill") (param i64 i64) (memory.fill (local.get 0) (i32.const 0x5a) (local.get 1)))
  (func (export "copy") (param i64 i64 i64) (memory.copy (local.get 0) (local.get 1) (local.get 2)))

  ;; a store, then a load whose range reaches one byte further: the
  ;; store happens before the load traps
  (func (export "storethenload") (param i64 i64) (result i64)
    (i64.store (local.get 0) (local.get 1))
    (i64.load offset=1 (local.get 0)))

  ;; two loads off one address, the second reaching further: one check
  ;; can stand for both
  (func (export "loadpair") (param i64) (result i64)
    (i64.add (i64.load (local.get 0)) (i64.load offset=8 (local.get 0))))
  ;; a load at addr+8 (an i64.add), then one at addr: when addr+8 wraps
  ;; past 2^64 the first is in bounds and the second is not
  (func (export "loadwrap") (param i64) (result i64)
    (i64.add (i64.load (i64.add (local.get 0) (i64.const 8))) (i64.load (local.get 0))))
  ;; a load, then a store reaching further off the same address
  (func (export "loadthenstore") (param i64)
    (i64.store offset=8 (local.get 0) (i64.load (local.get 0))))
  ;; a wide load before a branch, a narrower one inside it
  (func (export "loadbranch") (param i64 i32) (result i64)
    (local i64)
    (local.set 2 (i64.load offset=8 (local.get 0)))
    (if (local.get 1)
      (then (local.set 2 (i64.add (local.get 2) (i64.load (local.get 0))))))
    (local.get 2))

  ;; memory.grow inside the function that accesses the new page
  (func (export "growload") (param i64) (result i32)
    (drop (memory.grow (i64.const 1)))
    (i32.load8_u (local.get 0)))

  (func (export "size") (result i64) (memory.size))
  (func (export "grow") (param i64) (result i64) (memory.grow (local.get 0))))
