;; cg_func_import_refs.wat — imported functions referenced other than by a
;; call: one is exported, sits in an element segment and is reached through
;; call_indirect, another is the start function, a third is exported under a
;; bulk-dispatch name (w_<svc>_<mt>). A global import comes first, so the
;; function indices of the imports are not their indices among all the
;; imports. The memory gives the module its NewWithMemory and
;; NewFromSnapshot constructors.
(module
  (import "env" "g" (global $g i32))
  (import "env" "add" (func $add (param i32) (result i32)))
  (import "env" "init" (func $init))
  (import "env" "pack" (func $pack (param i32 i32) (result i64)))

  (memory 1)

  (type $unary (func (param i32) (result i32)))
  (table 2 funcref)
  (elem (i32.const 1) $add)

  (start $init)
  (export "add" (func $add))
  (export "w_1_2" (func $pack))

  ;; calls slot 1 of the table, which holds the import
  (func (export "viaTable") (param i32) (result i32)
    (call_indirect (type $unary) (local.get 0) (i32.const 1)))

  (func (export "load") (result i32)
    (i32.load (i32.const 0)))
)
