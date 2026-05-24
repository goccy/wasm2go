;; cg_bigdispatch.wat - large br_table dispatcher (void result) to trigger
;; dispatch_split.go. n nested blocks; br_table picks one; each end stores a
;; distinct value into a global, then returns. Void result so the dispatcher
;; split heuristic (which only fires on result-less funcs) can engage.
(module
  (global $out (mut i32) (i32.const 0))
  (func (export "dispatch") (param $sel i32)
    (local $acc i32)
    (block
      (block
        (block
          (block
            (block
              (block
                (block
                  (block
                    (block
                      (block
                        (block
                          (block
                            (block
                              (block
                                (block
                                  (block
                                    (block
                                      (block
                                        (block
                                          (block
                                            (block
                                              (block
                                                (block
                                                  (block
                                                    (block
                                                      (block
                                                        (block
                                                          (block
                                                            (block
                                                              (block
                                                                (block
                                                                  (block
                                                                    (block
                                                                      (block
                                                                        (block
                                                                          (block
                                                                            (block
                                                                              (block
                                                                                (block
                                                                                  (block
                                                                                    (block
                                                                                      (br_table 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 (local.get $sel))
                                                                                    )
                                                                                    (global.set $out (i32.const 100))
                                                                                    (return)
                                                                                  )
                                                                                  (global.set $out (i32.const 200))
                                                                                  (return)
                                                                                )
                                                                                (global.set $out (i32.const 300))
                                                                                (return)
                                                                              )
                                                                              (global.set $out (i32.const 400))
                                                                              (return)
                                                                            )
                                                                            (global.set $out (i32.const 500))
                                                                            (return)
                                                                          )
                                                                          (global.set $out (i32.const 600))
                                                                          (return)
                                                                        )
                                                                        (global.set $out (i32.const 700))
                                                                        (return)
                                                                      )
                                                                      (global.set $out (i32.const 800))
                                                                      (return)
                                                                    )
                                                                    (global.set $out (i32.const 900))
                                                                    (return)
                                                                  )
                                                                  (global.set $out (i32.const 1000))
                                                                  (return)
                                                                )
                                                                (global.set $out (i32.const 1100))
                                                                (return)
                                                              )
                                                              (global.set $out (i32.const 1200))
                                                              (return)
                                                            )
                                                            (global.set $out (i32.const 1300))
                                                            (return)
                                                          )
                                                          (global.set $out (i32.const 1400))
                                                          (return)
                                                        )
                                                        (global.set $out (i32.const 1500))
                                                        (return)
                                                      )
                                                      (global.set $out (i32.const 1600))
                                                      (return)
                                                    )
                                                    (global.set $out (i32.const 1700))
                                                    (return)
                                                  )
                                                  (global.set $out (i32.const 1800))
                                                  (return)
                                                )
                                                (global.set $out (i32.const 1900))
                                                (return)
                                              )
                                              (global.set $out (i32.const 2000))
                                              (return)
                                            )
                                            (global.set $out (i32.const 2100))
                                            (return)
                                          )
                                          (global.set $out (i32.const 2200))
                                          (return)
                                        )
                                        (global.set $out (i32.const 2300))
                                        (return)
                                      )
                                      (global.set $out (i32.const 2400))
                                      (return)
                                    )
                                    (global.set $out (i32.const 2500))
                                    (return)
                                  )
                                  (global.set $out (i32.const 2600))
                                  (return)
                                )
                                (global.set $out (i32.const 2700))
                                (return)
                              )
                              (global.set $out (i32.const 2800))
                              (return)
                            )
                            (global.set $out (i32.const 2900))
                            (return)
                          )
                          (global.set $out (i32.const 3000))
                          (return)
                        )
                        (global.set $out (i32.const 3100))
                        (return)
                      )
                      (global.set $out (i32.const 3200))
                      (return)
                    )
                    (global.set $out (i32.const 3300))
                    (return)
                  )
                  (global.set $out (i32.const 3400))
                  (return)
                )
                (global.set $out (i32.const 3500))
                (return)
              )
              (global.set $out (i32.const 3600))
              (return)
            )
            (global.set $out (i32.const 3700))
            (return)
          )
          (global.set $out (i32.const 3800))
          (return)
        )
        (global.set $out (i32.const 3900))
        (return)
      )
      (global.set $out (i32.const 4000))
      (return)
    )
    (global.set $out (i32.const 4100))
    (return)
  )
  (func (export "get_out") (result i32) (global.get $out))
)
