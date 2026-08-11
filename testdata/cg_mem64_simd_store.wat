;; Memory64 twin of cg_simd_store32.wat: identical store-sink shape
;; with i64 addressing. Window fusion must treat the simd_m64_* store
;; exactly like its wasm32 twin.
(module
  (memory (export "memory") i64 1)
  (func (export "scale2") (param $p i64)
    (v128.store (local.get $p)
      (f32x4.mul (v128.load (local.get $p))
                 (v128.load offset=64 (local.get $p))))
    (v128.store offset=16 (local.get $p)
      (f32x4.mul (v128.load offset=16 (local.get $p))
                 (v128.load offset=80 (local.get $p))))))
