;; cg_sharedimage.wat with its last data segment high in a large memory: the
;; data end is 24 MiB in, so a copy of the memory below it (AnonymousMemory)
;; takes long enough for the collector to run meanwhile. The start section
;; also touches one byte of every 64 KiB below the data end, so that the
;; pages a copy has to read are spread over the whole range.
(module
  (memory (export "memory") 512)

  (data $late "END")
  (data $early "hello shared image")

  (func $start (local $at i32)
    i32.const 25165824
    i32.const 0
    i32.const 3
    memory.init $late
    i32.const 1024
    i32.const 0
    i32.const 18
    memory.init $early
    (loop $touch
      local.get $at
      i32.const 7
      i32.store8
      local.get $at
      i32.const 65536
      i32.add
      local.tee $at
      i32.const 25165824
      i32.lt_u
      br_if $touch))
  (start $start)

  (func (export "peek") (param i32) (result i32)
    local.get 0
    i32.load8_u))
