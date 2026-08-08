;; memory64 semantics: i64 addressing, i64 size/grow, bulk ops and the
;; SIMD memory family on a 64-bit-indexed memory. Small memory sizes —
;; the >4GiB path is exercised by a separate gated test.
(module
  (memory i64 2 16)
  (data (i64.const 65600) "\01\02\03\04\05\06\07\08")

  ;; store/load roundtrip at base+offset, with a memarg offset
  (func (export "rw") (param i64 i64) (result i64)
    (i64.store offset=32 (local.get 0) (local.get 1))
    (i64.load offset=32 (local.get 0)))

  ;; sub-word store/load with sign extension
  (func (export "rw8") (param i64 i32) (result i32)
    (i32.store8 (local.get 0) (local.get 1))
    (i32.load8_s (local.get 0)))

  ;; address arithmetic is i64: base + dynamic scaled index
  (func (export "rwidx") (param i64 i64 i32) (result i32)
    (i32.store (i64.add (local.get 0) (i64.mul (local.get 1) (i64.const 4))) (local.get 2))
    (i32.load (i64.add (local.get 0) (i64.mul (local.get 1) (i64.const 4)))))

  ;; memory.size / memory.grow speak i64 pages
  (func (export "size") (result i64) (memory.size))
  (func (export "grow") (param i64) (result i64) (memory.grow (local.get 0)))

  ;; bulk ops: fill then copy then readback
  (func (export "bulk") (param i64 i64) (result i32)
    (memory.fill (local.get 0) (i32.const 0xa5) (i64.const 64))
    (memory.copy (local.get 1) (local.get 0) (i64.const 64))
    (i32.load8_u (i64.add (local.get 1) (i64.const 63))))

  ;; data segment placed via i64.const
  (func (export "dataseg") (result i64)
    (i64.load (i64.const 65600)))

  ;; v128 store/load roundtrip on an i64 address
  (func (export "vmem") (param i64) (result i64)
    (v128.store (local.get 0) (v128.const i64x2 0x1122334455667788 0x99aabbccddeeff00))
    (i64x2.extract_lane 1 (v128.load (local.get 0))))

  ;; widening load: bytes 1..8 of the data segment, sign-extended to i16
  (func (export "vwiden") (result i32)
    (i16x8.extract_lane_s 7 (v128.load8x8_s (i64.const 65600))))

  ;; splat and lane ops on i64 addresses
  (func (export "vsplat") (param i64) (result i32)
    (i32.store (local.get 0) (i32.const 0x0badf00d))
    (v128.store offset=16 (local.get 0) (v128.load32_splat (local.get 0)))
    (i32.load offset=28 (local.get 0)))

  (func (export "vlane") (param i64) (result i32)
    (i32.store (local.get 0) (i32.const 0x11223344))
    (v128.store offset=16 (local.get 0)
      (v128.load32_lane 2 (local.get 0) (v128.const i64x2 0 0)))
    (i32.load offset=24 (local.get 0))))
