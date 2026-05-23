(module
  ;; Mirrors C++ virtual method dispatch via call_indirect:
  ;; Each "object" has a vtable pointer at offset 0. The vtable is an
  ;; array of function indexes. Calling a virtual method:
  ;;   vtable = *(obj + 0)
  ;;   fn_idx = *(vtable + slot * 4)
  ;;   call_indirect(fn_idx, obj, args...)
  (memory (export "memory") 1)

  (table 8 funcref)
  (type $unop (func (param i32) (result i32)))
  (type $binop (func (param i32 i32) (result i32)))

  ;; Two "classes": Cat returns 1 from area, Square returns side*side.
  (func $cat_area  (param $self i32) (result i32) (i32.const 1))
  (func $cat_kind  (param $self i32) (result i32) (i32.const 100))
  (func $sq_area   (param $self i32) (result i32)
    (i32.mul (i32.load (i32.add (local.get $self) (i32.const 4)))
             (i32.load (i32.add (local.get $self) (i32.const 4)))))
  (func $sq_kind   (param $self i32) (result i32) (i32.const 200))
  (elem (i32.const 0) $cat_area $cat_kind $sq_area $sq_kind)

  ;; Object layout: { vtable_idx: i32 @0, side: i32 @4 }
  ;;   cat at 32   { vtable=0 (cat_area, cat_kind), side=ignored }
  ;;   sq at 48    { vtable=8 (sq_area,  sq_kind),  side=5 }
  ;; vtable_0 at 64: [0, 1]   ;; index 0 → cat_area, 1 → cat_kind
  ;; vtable_1 at 72: [2, 3]
  (data (i32.const 32) "\40\00\00\00\00\00\00\00")  ;; vtable=64, side=0
  (data (i32.const 48) "\48\00\00\00\05\00\00\00")  ;; vtable=72, side=5
  (data (i32.const 64) "\00\00\00\00\01\00\00\00")  ;; [0, 1]
  (data (i32.const 72) "\02\00\00\00\03\00\00\00")  ;; [2, 3]

  ;; obj.method(slot) — vtable[slot] called as unop(obj).
  (func (export "call_method") (param $obj i32) (param $slot i32) (result i32)
    (local $vt i32)
    (local $fn i32)
    (local.set $vt (i32.load (local.get $obj)))
    (local.set $fn (i32.load
      (i32.add (local.get $vt) (i32.mul (local.get $slot) (i32.const 4)))))
    (call_indirect (type $unop) (local.get $obj) (local.get $fn))))
