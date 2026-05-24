;; cli_start.wat — minimal module with a start section.
;; Used by cmd/wasm2go tests to verify that -dump prints "start: func N".
(module
  (type (;0;) (func))
  (func (;0;) (type 0)
    nop)
  (func (;1;) (type 0))
  (export "noop" (func 1))
  (start 0))
