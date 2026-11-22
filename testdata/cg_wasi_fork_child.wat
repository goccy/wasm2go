;; cg_wasi_fork_child.wat — imports from wasi_snapshot_preview1 and from env,
;; and exports __wasip1_posix_extension_fork_child, the entry of the child of
;; a fork. The child's result is made of what it sees: its argc (wasi), the
;; cell at 100 (memory), the global $g and env's base; it then changes the
;; cell and $g. The passive data segments, the memory's maximum and the
;; reference-typed global $r are the rest of the state a fork carries.
(module
  (import "wasi_snapshot_preview1" "args_sizes_get"
    (func $args_sizes_get (param i32 i32) (result i32)))
  (import "env" "base" (func $base (result i32)))

  (memory (export "memory") 1 3)
  (global $g (mut i32) (i32.const 0))
  (global $r (mut externref) (ref.null extern))
  (data $p0 "abcd")
  (data $p1 "efgh")

  (func (export "set") (param $v i32)
    (i32.store (i32.const 100) (local.get $v))
    (global.set $g (i32.mul (local.get $v) (i32.const 2))))

  (func (export "cell") (result i32)
    (i32.load (i32.const 100)))

  (func (export "g") (result i32)
    (global.get $g))

  ;; grows the memory by a page: the old size in pages, or -1
  (func (export "grow") (result i32)
    (memory.grow (i32.const 1)))

  (func (export "drop")
    (data.drop $p0))

  ;; copies $p0 to 300, which traps once $p0 is dropped
  (func (export "init0")
    (memory.init $p0 (i32.const 300) (i32.const 0) (i32.const 4)))

  ;; copies $p1 to 40000, where the data then ends
  (func (export "init1")
    (memory.init $p1 (i32.const 40000) (i32.const 0) (i32.const 4)))

  ;; argc + 10*cell + 100*g + 1000*base
  (func (export "__wasip1_posix_extension_fork_child") (result i32)
    (local $r i32)
    (drop (call $args_sizes_get (i32.const 200) (i32.const 204)))
    (local.set $r
      (i32.add
        (i32.add (i32.load (i32.const 200)) (i32.mul (i32.load (i32.const 100)) (i32.const 10)))
        (i32.add (i32.mul (global.get $g) (i32.const 100)) (i32.mul (call $base) (i32.const 1000)))))
    (i32.store (i32.const 100) (i32.const -1))
    (global.set $g (i32.const 9))
    (local.get $r))
)
