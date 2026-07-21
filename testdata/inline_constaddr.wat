;; Fixture for the SSA-constant-base literal-pool guard: a leaf callee
;; whose address param is used by MULTIPLE loads (so the constant
;; argument is hoisted into a Go local after inlining) is called with a
;; large constant address. The paired adjacent loads reproduce the
;; LDPSW-fusion shape that overflowed the arm64 literal pool on the
;; SpiderMonkey bundle. Memory is declared big enough that the address
;; is only reachable after growth; the loads are never executed at
;; test time — this fixture exists for compile/emit-shape checking.
(module
  (memory 1 512)
  (func $reader (param $p i32) (result i32)
    (i32.add
      (i32.add
        (i32.load (local.get $p))
        (i32.load offset=8 (local.get $p)))
      (i32.load offset=16 (local.get $p))))
  (func (export "big") (result i32)
    (call $reader (i32.const 27000000))))
