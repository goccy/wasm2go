(module
  ;; Mirrors a "C++ static initializer" pattern: a tree of records,
  ;; each holding {flag i8, child_count i32 @20, children_ptr i32 @24}.
  ;; init_node walks the tree, marking each node initialized, recursing into
  ;; non-null children. After traversal, init_node verifies the result of
  ;; some computation against an expected value — mismatch triggers a trap.
  (memory (export "memory") 1)

  ;; Three records laid out in memory:
  ;;   record A @ 32  (flag=0, side=0, ?, ?, ?, count=2, children_ptr=80)
  ;;   record B @ 64  (flag=0, side=0, ?, ?, ?, count=0, children_ptr=0)
  ;;   record C @ 96  (flag=0, side=0, ?, ?, ?, count=0, children_ptr=0)
  ;; pointer table @ 80: [64, 96]
  (data (i32.const 32)
        "\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\02\00\00\00\50\00\00\00")
  (data (i32.const 64)
        "\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00")
  (data (i32.const 80)
        "\40\00\00\00\60\00\00\00")
  (data (i32.const 96)
        "\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00")

  ;; Counter incremented every time init_node visits a fresh node.
  (data (i32.const 128) "\00\00\00\00")

  (func $init_node (param $node i32)
    (local $count i32)
    (local $children i32)
    (local $i i32)
    (local $child i32)
    ;; if node.flag != 0, return (already initialized)
    (if (i32.load8_u (local.get $node))
      (then (return)))
    ;; mark initialized
    (i32.store8 (local.get $node) (i32.const 1))
    ;; bump global visit counter
    (i32.store (i32.const 128)
      (i32.add (i32.load (i32.const 128)) (i32.const 1)))
    ;; load count + children pointer
    (local.set $count (i32.load (i32.add (local.get $node) (i32.const 20))))
    (local.set $children (i32.load (i32.add (local.get $node) (i32.const 24))))
    (local.set $i (i32.const 0))
    (block $exit
      (loop $body
        (br_if $exit (i32.eqz (local.get $count)))
        ;; child = *(children + i*4)
        (local.set $child (i32.load (i32.add (local.get $children) (local.get $i))))
        (if (local.get $child)
          (then (call $init_node (local.get $child))))
        (local.set $i (i32.add (local.get $i) (i32.const 4)))
        (local.set $count (i32.sub (local.get $count) (i32.const 1)))
        (br $body))))

  (func (export "run") (result i32)
    (call $init_node (i32.const 32))
    (i32.load (i32.const 128)))

  ;; Probes for individual fields after run.
  (func (export "flag_of") (param $addr i32) (result i32)
    (i32.load8_u (local.get $addr))))
