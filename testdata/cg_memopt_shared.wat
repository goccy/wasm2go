;; Regression fixture for the shared-memory MemOpt gate.
;;
;; The memory is declared shared (threads proposal), so redundant-load
;; elimination / store-to-load forwarding are UNSOUND: a peer agent may
;; write the address between the two loads, and each non-atomic load must
;; re-read memory. `redundant_load` issues two i32.load of the SAME address
;; with nothing between them — MemOpt would merge them into one on a
;; non-shared memory, but must NOT here. The codegen test asserts both
;; loads survive (and that forcing MemOpt on via WASM2GO_MEMOPT_ON_SHARED
;; collapses them, proving the gate is what preserves the second read).
(module
  (memory 1 1 shared)
  (func (export "redundant_load") (param $p i32) (result i32)
    (i32.add
      (i32.load (local.get $p))
      (i32.load (local.get $p)))))
