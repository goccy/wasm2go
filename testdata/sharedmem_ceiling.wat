;; sharedmem_ceiling.wat — a shared memory whose declared maximum (16384
;; pages = 1 GiB) dwarfs what the module touches, plus a small data
;; segment so the image machinery has a dataEnd. Exercised two ways:
;;   - sharedmem_alloc: building and discarding instances must hold RSS
;;     far under the ceiling (the Go allocator zeroing a reused
;;     ceiling-sized heap span was the regression).
;;   - sharedimage_inplace: `touch` writes BSS through an in-place image
;;     builder; a snapshot instance must inherit the write, a
;;     data-segment-image instance must not (the tail is punched).
(module
  (memory 16 16384 shared)
  (data (i32.const 0) "seg!")
  (func (export "touch") (param i32) (result i32)
    (i32.store (i32.const 64) (local.get 0))
    (i32.load (i32.const 64)))
  (func (export "peek") (result i32)
    (i32.load (i32.const 64))))
