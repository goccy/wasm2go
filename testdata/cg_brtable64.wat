(module
  ;; 64-way arity-0 br_table dispatcher — the computed-goto shape a
  ;; bytecode interpreter compiles to. Case k returns k*10+7 (odd
  ;; constants so a mis-routed binary-search tree path is caught by
  ;; value, not just by reachability); out-of-range returns -1.
  (func (export "switch64") (param i32) (result i32)
    (block $d
      (block $b63
        (block $b62
          (block $b61
            (block $b60
              (block $b59
                (block $b58
                  (block $b57
                    (block $b56
                      (block $b55
                        (block $b54
                          (block $b53
                            (block $b52
                              (block $b51
                                (block $b50
                                  (block $b49
                                    (block $b48
                                      (block $b47
                                        (block $b46
                                          (block $b45
                                            (block $b44
                                              (block $b43
                                                (block $b42
                                                  (block $b41
                                                    (block $b40
                                                      (block $b39
                                                        (block $b38
                                                          (block $b37
                                                            (block $b36
                                                              (block $b35
                                                                (block $b34
                                                                  (block $b33
                                                                    (block $b32
                                                                      (block $b31
                                                                        (block $b30
                                                                          (block $b29
                                                                            (block $b28
                                                                              (block $b27
                                                                                (block $b26
                                                                                  (block $b25
                                                                                    (block $b24
                                                                                      (block $b23
                                                                                        (block $b22
                                                                                          (block $b21
                                                                                            (block $b20
                                                                                              (block $b19
                                                                                                (block $b18
                                                                                                  (block $b17
                                                                                                    (block $b16
                                                                                                      (block $b15
                                                                                                        (block $b14
                                                                                                          (block $b13
                                                                                                            (block $b12
                                                                                                              (block $b11
                                                                                                                (block $b10
                                                                                                                  (block $b9
                                                                                                                    (block $b8
                                                                                                                      (block $b7
                                                                                                                        (block $b6
                                                                                                                          (block $b5
                                                                                                                            (block $b4
                                                                                                                              (block $b3
                                                                                                                                (block $b2
                                                                                                                                  (block $b1
                                                                                                                                    (block $b0
                                                                                                                                      local.get 0
                                                                                                                                      br_table 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64
                                                                                                                                    )
                                                                                                                                    i32.const 7
                                                                                                                                    return
                                                                                                                                  )
                                                                                                                                  i32.const 17
                                                                                                                                  return
                                                                                                                                )
                                                                                                                                i32.const 27
                                                                                                                                return
                                                                                                                              )
                                                                                                                              i32.const 37
                                                                                                                              return
                                                                                                                            )
                                                                                                                            i32.const 47
                                                                                                                            return
                                                                                                                          )
                                                                                                                          i32.const 57
                                                                                                                          return
                                                                                                                        )
                                                                                                                        i32.const 67
                                                                                                                        return
                                                                                                                      )
                                                                                                                      i32.const 77
                                                                                                                      return
                                                                                                                    )
                                                                                                                    i32.const 87
                                                                                                                    return
                                                                                                                  )
                                                                                                                  i32.const 97
                                                                                                                  return
                                                                                                                )
                                                                                                                i32.const 107
                                                                                                                return
                                                                                                              )
                                                                                                              i32.const 117
                                                                                                              return
                                                                                                            )
                                                                                                            i32.const 127
                                                                                                            return
                                                                                                          )
                                                                                                          i32.const 137
                                                                                                          return
                                                                                                        )
                                                                                                        i32.const 147
                                                                                                        return
                                                                                                      )
                                                                                                      i32.const 157
                                                                                                      return
                                                                                                    )
                                                                                                    i32.const 167
                                                                                                    return
                                                                                                  )
                                                                                                  i32.const 177
                                                                                                  return
                                                                                                )
                                                                                                i32.const 187
                                                                                                return
                                                                                              )
                                                                                              i32.const 197
                                                                                              return
                                                                                            )
                                                                                            i32.const 207
                                                                                            return
                                                                                          )
                                                                                          i32.const 217
                                                                                          return
                                                                                        )
                                                                                        i32.const 227
                                                                                        return
                                                                                      )
                                                                                      i32.const 237
                                                                                      return
                                                                                    )
                                                                                    i32.const 247
                                                                                    return
                                                                                  )
                                                                                  i32.const 257
                                                                                  return
                                                                                )
                                                                                i32.const 267
                                                                                return
                                                                              )
                                                                              i32.const 277
                                                                              return
                                                                            )
                                                                            i32.const 287
                                                                            return
                                                                          )
                                                                          i32.const 297
                                                                          return
                                                                        )
                                                                        i32.const 307
                                                                        return
                                                                      )
                                                                      i32.const 317
                                                                      return
                                                                    )
                                                                    i32.const 327
                                                                    return
                                                                  )
                                                                  i32.const 337
                                                                  return
                                                                )
                                                                i32.const 347
                                                                return
                                                              )
                                                              i32.const 357
                                                              return
                                                            )
                                                            i32.const 367
                                                            return
                                                          )
                                                          i32.const 377
                                                          return
                                                        )
                                                        i32.const 387
                                                        return
                                                      )
                                                      i32.const 397
                                                      return
                                                    )
                                                    i32.const 407
                                                    return
                                                  )
                                                  i32.const 417
                                                  return
                                                )
                                                i32.const 427
                                                return
                                              )
                                              i32.const 437
                                              return
                                            )
                                            i32.const 447
                                            return
                                          )
                                          i32.const 457
                                          return
                                        )
                                        i32.const 467
                                        return
                                      )
                                      i32.const 477
                                      return
                                    )
                                    i32.const 487
                                    return
                                  )
                                  i32.const 497
                                  return
                                )
                                i32.const 507
                                return
                              )
                              i32.const 517
                              return
                            )
                            i32.const 527
                            return
                          )
                          i32.const 537
                          return
                        )
                        i32.const 547
                        return
                      )
                      i32.const 557
                      return
                    )
                    i32.const 567
                    return
                  )
                  i32.const 577
                  return
                )
                i32.const 587
                return
              )
              i32.const 597
              return
            )
            i32.const 607
            return
          )
          i32.const 617
          return
        )
        i32.const 627
        return
      )
      i32.const 637
      return
    )
    i32.const -1
  )

  ;; Payload-carrying br_table (branch arity 1) — pins the If-chain
  ;; fallback lowering that arity>0 tables keep using.
  (func (export "pick") (param i32) (result i32)
    (block $b (result i32)
      (block $a (result i32)
        i32.const 111
        local.get 0
        br_table 0 1 0
      )
      i32.const 1000
      i32.add
    )
  )
)
