;; A module shaped like LLVM's shared-memory output: the data segments are
;; PASSIVE and a start function installs them with memory.init. That is the
;; layout the shared-image runtime exists for — the segment destinations are
;; wasm constants the host never sees until the start section runs them, which
;; is why the Module has to learn dataEnd at run time rather than at codegen.
;;
;; Two segments, deliberately out of order, so dataEnd is a max and not "the
;; last one wins".
;;
;; The start section also leaves two marks that let a test tell the two kinds of
;; image apart: it BUMPS A COUNTER in memory (so a re-run is visible) and it
;; SETS A MUTABLE GLOBAL to a value its declared initializer does not have (so a
;; global that was not restored is visible). Between them they stand in for what
;; a real toolchain's start section does — installing the segments and setting
;; up the thread-local base — and for why a snapshot has to carry the globals.
(module
  (memory (export "memory") 2)

  (global $marker (mut i32) (i32.const 0))

  (data $late "END")   ;; goes high, installed first
  (data $early "hello shared image")

  (func $start
    ;; memory.init dst src len
    i32.const 4096
    i32.const 0
    i32.const 3
    memory.init $late
    i32.const 1024
    i32.const 0
    i32.const 18
    memory.init $early

    ;; runs++ at byte 100
    i32.const 100
    i32.const 100
    i32.load8_u
    i32.const 1
    i32.add
    i32.store8

    ;; the global the declared initializer does not give us
    i32.const 42
    global.set $marker)
  (start $start)

  (func (export "peek") (param i32) (result i32)
    local.get 0
    i32.load8_u)

  (func (export "poke") (param i32) (param i32)
    local.get 0
    local.get 1
    i32.store8)

  (func (export "marker") (result i32)
    global.get $marker))
