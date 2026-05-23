;; datacoalesce.wat — multiple data segments: two with a small gap (must
;; coalesce into one copy) and one far away (must stay a separate copy).
(module
  (memory 2)
  (data (i32.const 0) "AAAA")
  (data (i32.const 8) "BBBB")
  (data (i32.const 100000) "CC"))
