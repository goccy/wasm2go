;; Elementwise scale: two v128 store sinks whose values are nested
;; mul(load, load) trees — the minimal shape of ggml's conversion /
;; scale loops. The window fuser must fold each store with its value
;; tree (and, with two candidates, may merge both into one region).
(module
  (memory (export "memory") 1)
  (func (export "scale2") (param $p i32)
    (v128.store (local.get $p)
      (f32x4.mul (v128.load (local.get $p))
                 (v128.load offset=64 (local.get $p))))
    (v128.store offset=16 (local.get $p)
      (f32x4.mul (v128.load offset=16 (local.get $p))
                 (v128.load offset=80 (local.get $p))))))
