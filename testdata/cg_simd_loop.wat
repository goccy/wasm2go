;; A counted SIMD accumulation loop in the exact shape ggml's dot
;; kernels lower to: a do-while over v128 loads with a countdown
;; counter and pointer bumps. Exercises the SIMD loop unrolling pass
;; end to end (guard blocks, remainder loop, exit-join phis) together
;; with bounds-check coalescing and window fusion over the unrolled
;; body.
(module
  (memory (export "mem") 1)

  ;; seed8(addr, v): poke one byte, so tests can fill memory patterns.
  (func (export "seed8") (param $a i32) (param $v i32)
    (i32.store8 (local.get $a) (local.get $v)))

  ;; loopsum(p, n): sum the four i32 lanes of the i32x4-sum of n
  ;; consecutive 16-byte blocks at p.
  (func (export "loopsum") (param $p i32) (param $n i32) (result i32)
    (local $acc v128)
    (local $i i32)
    (local.set $i (local.get $n))
    (block $exit
      (br_if $exit (i32.eqz (local.get $n)))
      (loop $l
        (local.set $acc
          (i32x4.add (local.get $acc) (v128.load (local.get $p))))
        (local.set $p (i32.add (local.get $p) (i32.const 16)))
        (local.set $i (i32.sub (local.get $i) (i32.const 1)))
        (br_if $l (local.get $i))))
    (i32.add
      (i32.add (i32x4.extract_lane 0 (local.get $acc))
               (i32x4.extract_lane 1 (local.get $acc)))
      (i32.add (i32x4.extract_lane 2 (local.get $acc))
               (i32x4.extract_lane 3 (local.get $acc)))))

  ;; loopsum64(p, n): loopsum with an INT64 countdown — proves the
  ;; wide-counter fused-loop form end to end (carried accumulator,
  ;; 64-bit counter parameter, arithmetic and exit result).
  (func (export "loopsum64") (param $p i32) (param $n i64) (result i32)
    (local $acc v128)
    (local $i i64)
    (local.set $i (local.get $n))
    (block $exit
      (br_if $exit (i64.eqz (local.get $n)))
      (loop $l
        (local.set $acc
          (i32x4.add (local.get $acc) (v128.load (local.get $p))))
        (local.set $p (i32.add (local.get $p) (i32.const 16)))
        (local.set $i (i64.sub (local.get $i) (i64.const 1)))
        (br_if $l (i64.ne (local.get $i) (i64.const 0)))))
    (i32.add
      (i32.add (i32x4.extract_lane 0 (local.get $acc))
               (i32x4.extract_lane 1 (local.get $acc)))
      (i32.add (i32x4.extract_lane 2 (local.get $acc))
               (i32x4.extract_lane 3 (local.get $acc)))))

  ;; gemm4(a, b, n, stride): the f32 GEMM microkernel shape — four
  ;; carried accumulators fed by two shared loads and two shared
  ;; splats (a 2x2 outer-product step), an int64 countdown and a
  ;; runtime row stride. Mirrors ggml's fp32 matmul inner loop.
  (func (export "gemm4") (param $a i32) (param $b i32) (param $n i64) (param $s i32) (result i32)
    (local $acc00 v128)
    (local $acc01 v128)
    (local $acc10 v128)
    (local $acc11 v128)
    (local $x0 v128)
    (local $x1 v128)
    (local $s0 v128)
    (local $s1 v128)
    (local $i i64)
    (local.set $i (local.get $n))
    (block $exit
      (br_if $exit (i64.eqz (local.get $n)))
      (loop $l
        (local.set $x0 (v128.load (local.get $b)))
        (local.set $x1 (v128.load offset=16 (local.get $b)))
        (local.set $s0 (v128.load32_splat (local.get $a)))
        (local.set $s1 (v128.load32_splat offset=128 (local.get $a)))
        (local.set $acc00 (f32x4.add (local.get $acc00) (f32x4.mul (local.get $x0) (local.get $s0))))
        (local.set $acc01 (f32x4.add (local.get $acc01) (f32x4.mul (local.get $x0) (local.get $s1))))
        (local.set $acc10 (f32x4.add (local.get $acc10) (f32x4.mul (local.get $x1) (local.get $s0))))
        (local.set $acc11 (f32x4.add (local.get $acc11) (f32x4.mul (local.get $x1) (local.get $s1))))
        (local.set $a (i32.add (local.get $a) (i32.const 4)))
        (local.set $b (i32.add (local.get $b) (local.get $s)))
        (local.set $i (i64.sub (local.get $i) (i64.const 1)))
        (br_if $l (i64.ne (local.get $i) (i64.const 0)))))
    (local.set $x0
      (i32x4.add
        (i32x4.add (local.get $acc00) (local.get $acc01))
        (i32x4.add (local.get $acc10) (local.get $acc11))))
    (i32.add
      (i32.add (i32x4.extract_lane 0 (local.get $x0))
               (i32x4.extract_lane 1 (local.get $x0)))
      (i32.add (i32x4.extract_lane 2 (local.get $x0))
               (i32x4.extract_lane 3 (local.get $x0)))))

  ;; quantnarrow(p, n): the quantize-kernel shape — float loads scaled,
  ;; rounded, saturating-truncated, then narrowed twice (i32x4→i16x8→
  ;; i8x16) and lane-summed. The narrowing second halves (sqxtn2-class)
  ;; write only their destination's high half and PRESERVE the low —
  ;; the destination-as-input shape that register renumbering must
  ;; refuse (a bug here once produced garbage generation).
  (func (export "quantnarrow") (param $p i32) (param $n i32) (result i32)
    (local $acc i32)
    (local $i i32)
    (local $v v128)
    (local.set $i (local.get $n))
    (block $exit
      (br_if $exit (i32.eqz (local.get $n)))
      (loop $l
        (local.set $v
          (i8x16.narrow_i16x8_s
            (i16x8.narrow_i32x4_s
              (i32x4.trunc_sat_f32x4_s
                (f32x4.nearest
                  (f32x4.mul (v128.load (local.get $p))
                             (f32x4.splat (f32.const 0.5)))))
              (i32x4.trunc_sat_f32x4_s
                (f32x4.nearest
                  (f32x4.mul (v128.load offset=16 (local.get $p))
                             (f32x4.splat (f32.const 0.25))))))
            (i16x8.narrow_i32x4_s
              (i32x4.trunc_sat_f32x4_s
                (f32x4.nearest
                  (f32x4.mul (v128.load offset=32 (local.get $p))
                             (f32x4.splat (f32.const 2.0)))))
              (i32x4.trunc_sat_f32x4_s
                (f32x4.nearest
                  (f32x4.mul (v128.load offset=48 (local.get $p))
                             (f32x4.splat (f32.const 4.0))))))))
        (local.set $acc
          (i32.add (local.get $acc)
            (i32.add
              (i32.add (i8x16.extract_lane_s 0 (local.get $v))
                       (i8x16.extract_lane_s 5 (local.get $v)))
              (i32.add (i8x16.extract_lane_s 10 (local.get $v))
                       (i8x16.extract_lane_s 15 (local.get $v))))))
        (local.set $p (i32.add (local.get $p) (i32.const 64)))
        (local.set $i (i32.sub (local.get $i) (i32.const 1)))
        (br_if $l (local.get $i))))
    (local.get $acc))

  ;; scaledot(x, y, n): the quantized-kernel scale-lookup shape — each
  ;; 18-byte block starts with a u16 table index whose f32 entry
  ;; (table at 768) scales the block product. The u16 load, shift,
  ;; table-base add, f32 loads and f32 multiply form the scalar chain
  ;; the fused-region chase internalizes.
  (func (export "scaledot") (param $x i32) (param $y i32) (param $n i32) (result i32)
    (local $acc v128)
    (local $i i32)
    (local.set $i (local.get $n))
    (block $exit
      (br_if $exit (i32.eqz (local.get $n)))
      (loop $l
        (local.set $acc
          (f32x4.add (local.get $acc)
            (f32x4.mul
              (f32x4.splat
                (f32.mul
                  (f32.load (i32.add
                    (i32.shl (i32.load16_u (local.get $x)) (i32.const 2))
                    (i32.const 768)))
                  (f32.load (i32.add
                    (i32.shl (i32.load16_u (local.get $y)) (i32.const 2))
                    (i32.const 768)))))
              (f32x4.mul
                (f32x4.convert_i32x4_s (v128.load offset=2 (local.get $x)))
                (f32x4.convert_i32x4_s (v128.load offset=2 (local.get $y)))))))
        (local.set $x (i32.add (local.get $x) (i32.const 18)))
        (local.set $y (i32.add (local.get $y) (i32.const 18)))
        (local.set $i (i32.sub (local.get $i) (i32.const 1)))
        (br_if $l (local.get $i))))
    (i32.add
      (i32.add
        (i32x4.extract_lane 0 (i32x4.trunc_sat_f32x4_s (local.get $acc)))
        (i32x4.extract_lane 1 (i32x4.trunc_sat_f32x4_s (local.get $acc))))
      (i32.add
        (i32x4.extract_lane 2 (i32x4.trunc_sat_f32x4_s (local.get $acc)))
        (i32x4.extract_lane 3 (i32x4.trunc_sat_f32x4_s (local.get $acc))))))

  ;; axpy(x, y, n): the store-sink shape — per block, y is rewritten
  ;; as the f32 sum of the converted x and y blocks. Exercises stores
  ;; as fused-window sinks (memory-op ordering, the no-result region
  ;; form, and the checked store splice).
  (func (export "axpy") (param $x i32) (param $y i32) (param $n i32)
    (local $i i32)
    (local.set $i (local.get $n))
    (block $exit
      (br_if $exit (i32.eqz (local.get $n)))
      (loop $l
        (v128.store (local.get $y)
          (f32x4.add
            (f32x4.convert_i32x4_s (v128.load (local.get $y)))
            (f32x4.convert_i32x4_s (v128.load (local.get $x)))))
        (local.set $x (i32.add (local.get $x) (i32.const 16)))
        (local.set $y (i32.add (local.get $y) (i32.const 16)))
        (local.set $i (i32.sub (local.get $i) (i32.const 1)))
        (br_if $l (local.get $i)))))

  ;; strideaxpy(x, y, n, stride): axpy whose pointer advance is a
  ;; RUNTIME stride — the loop-fusion bump must ride as a delta
  ;; parameter instead of an immediate.
  (func (export "strideaxpy") (param $x i32) (param $y i32) (param $n i32) (param $s i32)
    (local $i i32)
    (local.set $i (local.get $n))
    (block $exit
      (br_if $exit (i32.eqz (local.get $n)))
      (loop $l
        (v128.store (local.get $y)
          (f32x4.add
            (f32x4.convert_i32x4_s (v128.load (local.get $y)))
            (f32x4.convert_i32x4_s (v128.load (local.get $x)))))
        (local.set $x (i32.add (local.get $x) (local.get $s)))
        (local.set $y (i32.add (local.get $y) (local.get $s)))
        (local.set $i (i32.sub (local.get $i) (i32.const 1)))
        (br_if $l (local.get $i)))))

  ;; axpy64(x, y, n): axpy driven by an INT64 countdown — the fused
  ;; loop's counter parameter, arithmetic and exit result must all be
  ;; 64-bit while the pointers stay i32.
  (func (export "axpy64") (param $x i32) (param $y i32) (param $n i64)
    (local $i i64)
    (local.set $i (local.get $n))
    (block $exit
      (br_if $exit (i64.eqz (local.get $n)))
      (loop $l
        (v128.store (local.get $y)
          (f32x4.add
            (f32x4.convert_i32x4_s (v128.load (local.get $y)))
            (f32x4.convert_i32x4_s (v128.load (local.get $x)))))
        (local.set $x (i32.add (local.get $x) (i32.const 16)))
        (local.set $y (i32.add (local.get $y) (i32.const 16)))
        (local.set $i (i64.sub (local.get $i) (i64.const 1)))
        (br_if $l (i64.ne (local.get $i) (i64.const 0))))))

  ;; gathersum(p, n): the lane-insert gather shape — a vector built
  ;; from four strided 32-bit loads (zero + three lane inserts) plus a
  ;; widening 16x4 load, accumulated as i32x4. Exercises the fused
  ;; lane-load vocabulary.
  (func (export "gathersum") (param $p i32) (param $n i32) (result i32)
    (local $acc v128)
    (local $i i32)
    (local $v v128)
    (local.set $i (local.get $n))
    (block $exit
      (br_if $exit (i32.eqz (local.get $n)))
      (loop $l
        (local.set $v (v128.load32_zero (local.get $p)))
        (local.set $v (v128.load32_lane offset=20 1 (local.get $p) (local.get $v)))
        (local.set $v (v128.load32_lane offset=40 2 (local.get $p) (local.get $v)))
        (local.set $v (v128.load32_lane offset=60 3 (local.get $p) (local.get $v)))
        (local.set $acc (i32x4.add (local.get $acc) (local.get $v)))
        (local.set $acc (i32x4.add (local.get $acc)
          (v128.load16x4_u offset=8 (local.get $p))))
        (local.set $p (i32.add (local.get $p) (i32.const 24)))
        (local.set $i (i32.sub (local.get $i) (i32.const 1)))
        (br_if $l (local.get $i))))
    (i32.add
      (i32.add (i32x4.extract_lane 0 (local.get $acc))
               (i32x4.extract_lane 1 (local.get $acc)))
      (i32.add (i32x4.extract_lane 2 (local.get $acc))
               (i32x4.extract_lane 3 (local.get $acc)))))

  ;; dot2(x, y, n): two interleaved streams with widening multiplies —
  ;; the q8-style shape that the multi-root window fusion targets.
  (func (export "dot2") (param $x i32) (param $y i32) (param $n i32) (result i32)
    (local $acc v128)
    (local $i i32)
    (local.set $i (local.get $n))
    (block $exit
      (br_if $exit (i32.eqz (local.get $n)))
      (loop $l
        (local.set $acc
          (i32x4.add
            (local.get $acc)
            (i32x4.add
              (i32x4.dot_i16x8_s
                (i16x8.extend_low_i8x16_s (v128.load (local.get $x)))
                (i16x8.extend_low_i8x16_s (v128.load (local.get $y))))
              (i32x4.dot_i16x8_s
                (i16x8.extend_high_i8x16_s (v128.load (local.get $x)))
                (i16x8.extend_high_i8x16_s (v128.load (local.get $y)))))))
        (local.set $x (i32.add (local.get $x) (i32.const 16)))
        (local.set $y (i32.add (local.get $y) (i32.const 16)))
        (local.set $i (i32.sub (local.get $i) (i32.const 1)))
        (br_if $l (local.get $i))))
    (i32.add
      (i32.add (i32x4.extract_lane 0 (local.get $acc))
               (i32x4.extract_lane 1 (local.get $acc)))
      (i32.add (i32x4.extract_lane 2 (local.get $acc))
               (i32x4.extract_lane 3 (local.get $acc))))))
