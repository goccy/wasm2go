;; A memory64 module for the mappings of a memory that grows past 4 GiB.
;;
;; The start section installs one passive segment low in memory and, when
;; the memory already reaches past 4 GiB (an instance built on a memory of
;; that size), a second one above 2^32: its end is the module's dataEnd,
;; which a 32-bit field could not hold. peek/poke/grow/size take and return
;; the memory64's i64 addresses and page counts.
(module
  (memory i64 2)

  (data $low "hello memory64")
  (data $high "above 4 GiB")

  (func $start
    i64.const 1024
    i32.const 0
    i32.const 14
    memory.init $low

    memory.size
    i64.const 65537
    i64.ge_u
    if
      i64.const 0x100001000
      i32.const 0
      i32.const 11
      memory.init $high
    end)
  (start $start)

  (func (export "peek") (param i64) (result i32)
    local.get 0
    i32.load8_u)

  (func (export "poke") (param i64) (param i32)
    local.get 0
    local.get 1
    i32.store8)

  (func (export "grow") (param i64) (result i64)
    local.get 0
    memory.grow)

  (func (export "size") (result i64)
    memory.size))
