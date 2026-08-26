;; sharedmem_ceiling.wat — a shared memory whose declared maximum (16384
;; pages = 1 GiB) dwarfs what the module touches. The generated
;; constructor allocates shared memories at the ceiling; the
;; sharedmem_alloc test builds and discards several instances and holds
;; the process RSS far under the ceiling — the regression it pins is the
;; Go allocator zeroing a reused ceiling-sized heap span (make after a
;; discarded instance memclrs the whole span, gigabytes of dirty pages
;; for untouched memory).
(module
  (memory 16 16384 shared)
  (func (export "touch") (param i32) (result i32)
    (i32.store (i32.const 64) (local.get 0))
    (i32.load (i32.const 64))))
