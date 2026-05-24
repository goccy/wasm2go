;; cg_sharedexit.wat - big br_table dispatcher whose case bodies converge
;; on one shared epilogue section. The epilogue ($epi block end) is NOT a
;; br_table target, so it stays a shared-exit label that dispatch_split
;; inlines into each case sub-function. The default routes to a real case.
(module
  (global $out (mut i32) (i32.const 0))
  (func (export "dispatch") (param $sel i32)
    (local $acc i32)
    (block $epi
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
                                                                                      (br_table 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 39 (local.get $sel))
                                                                                    )
                                                                                    (local.set $acc (i32.add (local.get $acc) (i32.const 10)))
                                                                                    (br $epi)
                                                                                  )
                                                                                  (local.set $acc (i32.add (local.get $acc) (i32.const 20)))
                                                                                  (br $epi)
                                                                                )
                                                                                (local.set $acc (i32.add (local.get $acc) (i32.const 30)))
                                                                                (br $epi)
                                                                              )
                                                                              (local.set $acc (i32.add (local.get $acc) (i32.const 40)))
                                                                              (br $epi)
                                                                            )
                                                                            (local.set $acc (i32.add (local.get $acc) (i32.const 50)))
                                                                            (br $epi)
                                                                          )
                                                                          (local.set $acc (i32.add (local.get $acc) (i32.const 60)))
                                                                          (br $epi)
                                                                        )
                                                                        (local.set $acc (i32.add (local.get $acc) (i32.const 70)))
                                                                        (br $epi)
                                                                      )
                                                                      (local.set $acc (i32.add (local.get $acc) (i32.const 80)))
                                                                      (br $epi)
                                                                    )
                                                                    (local.set $acc (i32.add (local.get $acc) (i32.const 90)))
                                                                    (br $epi)
                                                                  )
                                                                  (local.set $acc (i32.add (local.get $acc) (i32.const 100)))
                                                                  (br $epi)
                                                                )
                                                                (local.set $acc (i32.add (local.get $acc) (i32.const 110)))
                                                                (br $epi)
                                                              )
                                                              (local.set $acc (i32.add (local.get $acc) (i32.const 120)))
                                                              (br $epi)
                                                            )
                                                            (local.set $acc (i32.add (local.get $acc) (i32.const 130)))
                                                            (br $epi)
                                                          )
                                                          (local.set $acc (i32.add (local.get $acc) (i32.const 140)))
                                                          (br $epi)
                                                        )
                                                        (local.set $acc (i32.add (local.get $acc) (i32.const 150)))
                                                        (br $epi)
                                                      )
                                                      (local.set $acc (i32.add (local.get $acc) (i32.const 160)))
                                                      (br $epi)
                                                    )
                                                    (local.set $acc (i32.add (local.get $acc) (i32.const 170)))
                                                    (br $epi)
                                                  )
                                                  (local.set $acc (i32.add (local.get $acc) (i32.const 180)))
                                                  (br $epi)
                                                )
                                                (local.set $acc (i32.add (local.get $acc) (i32.const 190)))
                                                (br $epi)
                                              )
                                              (local.set $acc (i32.add (local.get $acc) (i32.const 200)))
                                              (br $epi)
                                            )
                                            (local.set $acc (i32.add (local.get $acc) (i32.const 210)))
                                            (br $epi)
                                          )
                                          (local.set $acc (i32.add (local.get $acc) (i32.const 220)))
                                          (br $epi)
                                        )
                                        (local.set $acc (i32.add (local.get $acc) (i32.const 230)))
                                        (br $epi)
                                      )
                                      (local.set $acc (i32.add (local.get $acc) (i32.const 240)))
                                      (br $epi)
                                    )
                                    (local.set $acc (i32.add (local.get $acc) (i32.const 250)))
                                    (br $epi)
                                  )
                                  (local.set $acc (i32.add (local.get $acc) (i32.const 260)))
                                  (br $epi)
                                )
                                (local.set $acc (i32.add (local.get $acc) (i32.const 270)))
                                (br $epi)
                              )
                              (local.set $acc (i32.add (local.get $acc) (i32.const 280)))
                              (br $epi)
                            )
                            (local.set $acc (i32.add (local.get $acc) (i32.const 290)))
                            (br $epi)
                          )
                          (local.set $acc (i32.add (local.get $acc) (i32.const 300)))
                          (br $epi)
                        )
                        (local.set $acc (i32.add (local.get $acc) (i32.const 310)))
                        (br $epi)
                      )
                      (local.set $acc (i32.add (local.get $acc) (i32.const 320)))
                      (br $epi)
                    )
                    (local.set $acc (i32.add (local.get $acc) (i32.const 330)))
                    (br $epi)
                  )
                  (local.set $acc (i32.add (local.get $acc) (i32.const 340)))
                  (br $epi)
                )
                (local.set $acc (i32.add (local.get $acc) (i32.const 350)))
                (br $epi)
              )
              (local.set $acc (i32.add (local.get $acc) (i32.const 360)))
              (br $epi)
            )
            (local.set $acc (i32.add (local.get $acc) (i32.const 370)))
            (br $epi)
          )
          (local.set $acc (i32.add (local.get $acc) (i32.const 380)))
          (br $epi)
        )
        (local.set $acc (i32.add (local.get $acc) (i32.const 390)))
        (br $epi)
      )
      (local.set $acc (i32.add (local.get $acc) (i32.const 400)))
      (br $epi)
    )
    (global.set $out (i32.const 777)))
  (func (export "get_out") (result i32) (global.get $out))
)
