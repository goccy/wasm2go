#!/usr/bin/env python3
"""Generates the native SIMD helper assembly for wasm2go's helpers package.

Reads the scalar reference implementations' signatures from
internal/codegen/helpers/simd_scalar.go, then emits:

  simd_asm_arm64.s   NEON bodies. The Go assembler's NEON coverage is
                     spotty, so vector instructions are emitted as WORD
                     directives whose encodings come from assembling the
                     equivalent GAS text with clang (the encoder ground
                     truth); loads/stores/constants use native Go asm.
  simd_asm_decls.go  //go:build arm64 — body-less declarations for the
                     asm-covered ops, plus inlinable aliases onto the
                     _scalar bodies for the few uncovered ones.
  simd_fallback.go   //go:build !arm64 — aliases every op onto _scalar.

Register protocol (fixed, so encodings are constants): v128 args a/b/c in
V0/V1/V2, scalar int arg in R0, result vector in V0, result scalar in R0.
Every sequence is branch-free, so each GAS line encodes independently.

Usage: python3 tools/gen-simd-asm/gen.py  (from the repo root; needs clang
and llvm-objdump, e.g. from Homebrew LLVM)
"""

import re
import subprocess
import sys
import tempfile
import os

CLANG = os.environ.get("CLANG", "/opt/homebrew/opt/llvm/bin/clang")
OBJDUMP = os.environ.get("OBJDUMP", "/opt/homebrew/opt/llvm/bin/llvm-objdump")
HELPERS = "internal/codegen/helpers"

# ---------------------------------------------------------------------------
# aarch64 sequence table. Each entry: op name (without simd_ prefix) →
# list of lines. A line starting with "go:" is emitted as native Go asm;
# anything else is GAS assembled to a WORD directive.
# ---------------------------------------------------------------------------

A64 = {}

def seq(name, *lines):
    A64[name] = list(lines)

# ---- v128 logic ----
seq("v128_not", "mvn v0.16b, v0.16b")
seq("v128_and", "and v0.16b, v0.16b, v1.16b")
seq("v128_andnot", "bic v0.16b, v0.16b, v1.16b")
seq("v128_or", "orr v0.16b, v0.16b, v1.16b")
seq("v128_xor", "eor v0.16b, v0.16b, v1.16b")
# bitselect(a,b,c) = a&c | b&~c: BSL keeps mask in dst.
seq("v128_bitselect", "mov v3.16b, v2.16b", "bsl v3.16b, v0.16b, v1.16b", "mov v0.16b, v3.16b")
seq("v128_any_true", "umaxv b1, v0.16b", "umov w0, v1.b[0]", "cmp w0, #0", "cset w0, ne")
# f16x4_cvt_bits: the four f32 lanes converted to float16 and packed
# in x0 (16 bits per lane, little-endian). FCVTN gives the IEEE
# round-to-nearest-even conversion; NaN lanes are blended to
# sign|0x7E00 to match the software idiom this op replaces.
seq("f16x4_cvt_bits",
    "fcvtn v1.4h, v0.4s",
    "fcmeq v2.4s, v0.4s, v0.4s",
    "ushr v3.4s, v0.4s, #16",
    "movi v4.4s, #0x80, lsl #8",
    "and v3.16b, v3.16b, v4.16b",
    "movi v4.4s, #0x7e, lsl #8",
    "orr v3.16b, v3.16b, v4.16b",
    "xtn v2.4h, v2.4s",
    "xtn v3.4h, v3.4s",
    "bsl v2.8b, v1.8b, v3.8b",
    "go:FMOVD F2, R0")

# ---- integer families ----
for shape, T, n in [("i8x16", "16b", 16), ("i16x8", "8h", 8), ("i32x4", "4s", 4), ("i64x2", "2d", 2)]:
    seq(f"{shape}_add", f"add v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_sub", f"sub v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_neg", f"neg v0.{T}, v0.{T}")
    seq(f"{shape}_abs", f"abs v0.{T}, v0.{T}")
    seq(f"{shape}_eq", f"cmeq v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_ne", f"cmeq v0.{T}, v0.{T}, v1.{T}", f"mvn v0.16b, v0.16b")
    seq(f"{shape}_lt_s", f"cmgt v0.{T}, v1.{T}, v0.{T}")
    seq(f"{shape}_gt_s", f"cmgt v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_le_s", f"cmge v0.{T}, v1.{T}, v0.{T}")
    seq(f"{shape}_ge_s", f"cmge v0.{T}, v0.{T}, v1.{T}")
for shape, T in [("i8x16", "16b"), ("i16x8", "8h"), ("i32x4", "4s")]:
    if shape != "i8x16":
        seq(f"{shape}_mul", f"mul v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_lt_u", f"cmhi v0.{T}, v1.{T}, v0.{T}")
    seq(f"{shape}_gt_u", f"cmhi v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_le_u", f"cmhs v0.{T}, v1.{T}, v0.{T}")
    seq(f"{shape}_ge_u", f"cmhs v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_min_s", f"smin v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_min_u", f"umin v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_max_s", f"smax v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_max_u", f"umax v0.{T}, v0.{T}, v1.{T}")

# shifts: count arrives in w0; wasm masks it by lane width.
for shape, T, bits in [("i8x16", "16b", 8), ("i16x8", "8h", 16), ("i32x4", "4s", 32), ("i64x2", "2d", 64)]:
    mask = bits - 1
    # USHL/SSHL read each lane's shift from its LOW BYTE, so a w-register
    # dup is fine for every lane size; .2d dup just needs the x-form of
    # the register (the low byte is what matters, including the two's-
    # complement negative for right shifts).
    reg = "x0" if T == "2d" else "w0"
    seq(f"{shape}_shl",
        f"and w0, w0, #{mask}", f"dup v1.{T}, {reg}", f"ushl v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_shr_s",
        f"and w0, w0, #{mask}", "neg w0, w0", f"dup v1.{T}, {reg}", f"sshl v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_shr_u",
        f"and w0, w0, #{mask}", "neg w0, w0", f"dup v1.{T}, {reg}", f"ushl v0.{T}, v0.{T}, v1.{T}")

# saturating add/sub + averages (8/16-bit lanes)
for shape, T in [("i8x16", "16b"), ("i16x8", "8h")]:
    seq(f"{shape}_add_sat_s", f"sqadd v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_add_sat_u", f"uqadd v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_sub_sat_s", f"sqsub v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_sub_sat_u", f"uqsub v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_avgr_u", f"urhadd v0.{T}, v0.{T}, v1.{T}")

seq("i8x16_popcnt", "cnt v0.16b, v0.16b")
seq("i16x8_q15mulr_sat_s", "sqrdmulh v0.8h, v0.8h, v1.8h")

# all_true / bitmask
for shape, B, lane in [("i8x16", "b", "16b"), ("i16x8", "h", "8h"), ("i32x4", "s", "4s")]:
    seq(f"{shape}_all_true",
        f"uminv {B}1, v0.{lane}", f"umov w0, v1.{B}[0]", "cmp w0, #0", "cset w0, ne")
seq("i64x2_all_true",
    "cmeq v0.2d, v0.2d, #0", "mvn v0.16b, v0.16b",
    "uminv s1, v0.4s", "umov w0, v1.s[0]", "cmp w0, #0", "cset w0, ne")

seq("i8x16_bitmask",
    "sshr v1.16b, v0.16b, #7",
    "go:MOVD $·simdConstBitpos8(SB), R4",
    "go:FMOVQ (R4), F2",
    "and v1.16b, v1.16b, v2.16b",
    "umov x1, v1.d[0]",
    "umov x2, v1.d[1]",
    "go:MOVD $0x0101010101010101, R3",
    "mul x1, x1, x3",
    "mul x2, x2, x3",
    "lsr x1, x1, #56",
    "lsr x2, x2, #56",
    "orr w0, w1, w2, lsl #8")
seq("i16x8_bitmask",
    "sshr v1.8h, v0.8h, #15",
    "go:MOVD $·simdConstBitpos16(SB), R4",
    "go:FMOVQ (R4), F2",
    "and v1.16b, v1.16b, v2.16b",
    "addv h1, v1.8h",
    "umov w0, v1.h[0]")
seq("i32x4_bitmask",
    "sshr v1.4s, v0.4s, #31",
    "go:MOVD $·simdConstBitpos32(SB), R4",
    "go:FMOVQ (R4), F2",
    "and v1.16b, v1.16b, v2.16b",
    "addv s1, v1.4s",
    "umov w0, v1.s[0]")
seq("i64x2_bitmask",
    "umov x1, v0.d[0]",
    "umov x2, v0.d[1]",
    "lsr x1, x1, #63",
    "lsr x2, x2, #63",
    "orr w0, w1, w2, lsl #1")

# narrow / extend / extmul / extadd / dot
seq("i8x16_narrow_i16x8_s", "sqxtn v0.8b, v0.8h", "sqxtn2 v0.16b, v1.8h")
seq("i8x16_narrow_i16x8_u", "sqxtun v0.8b, v0.8h", "sqxtun2 v0.16b, v1.8h")
seq("i16x8_narrow_i32x4_s", "sqxtn v0.4h, v0.4s", "sqxtn2 v0.8h, v1.4s")
seq("i16x8_narrow_i32x4_u", "sqxtun v0.4h, v0.4s", "sqxtun2 v0.8h, v1.4s")
for dst, src, dT, sT in [("i16x8", "i8x16", "8h", "8b"), ("i32x4", "i16x8", "4s", "4h"), ("i64x2", "i32x4", "2d", "2s")]:
    sT2 = {"8b": "16b", "4h": "8h", "2s": "4s"}[sT]
    seq(f"{dst}_extend_low_{src}_s", f"sshll v0.{dT}, v0.{sT}, #0")
    seq(f"{dst}_extend_high_{src}_s", f"sshll2 v0.{dT}, v0.{sT2}, #0")
    seq(f"{dst}_extend_low_{src}_u", f"ushll v0.{dT}, v0.{sT}, #0")
    seq(f"{dst}_extend_high_{src}_u", f"ushll2 v0.{dT}, v0.{sT2}, #0")
    seq(f"{dst}_extmul_low_{src}_s", f"smull v0.{dT}, v0.{sT}, v1.{sT}")
    seq(f"{dst}_extmul_high_{src}_s", f"smull2 v0.{dT}, v0.{sT2}, v1.{sT2}")
    seq(f"{dst}_extmul_low_{src}_u", f"umull v0.{dT}, v0.{sT}, v1.{sT}")
    seq(f"{dst}_extmul_high_{src}_u", f"umull2 v0.{dT}, v0.{sT2}, v1.{sT2}")
seq("i16x8_extadd_pairwise_i8x16_s", "saddlp v0.8h, v0.16b")
seq("i16x8_extadd_pairwise_i8x16_u", "uaddlp v0.8h, v0.16b")
seq("i32x4_extadd_pairwise_i16x8_s", "saddlp v0.4s, v0.8h")
seq("i32x4_extadd_pairwise_i16x8_u", "uaddlp v0.4s, v0.8h")
seq("i32x4_dot_i16x8_s",
    "smull v2.4s, v0.4h, v1.4h",
    "smull2 v3.4s, v0.8h, v1.8h",
    "addp v0.4s, v2.4s, v3.4s")

# swizzle / shuffle / splats
seq("i8x16_swizzle", "tbl v0.16b, {v0.16b}, v1.16b")
seq("i8x16_shuffle", "tbl v0.16b, {v0.16b, v1.16b}, v2.16b")
seq("i8x16_splat", "dup v0.16b, w0")
seq("i16x8_splat", "dup v0.8h, w0")
seq("i32x4_splat", "dup v0.4s, w0")
seq("i64x2_splat", "dup v0.2d, x0")
seq("f32x4_splat", "dup v0.4s, v0.s[0]")   # arg preloaded into s0
seq("f64x2_splat", "dup v0.2d, v0.d[0]")   # arg preloaded into d0

# ---- floats ----
for shape, T in [("f32x4", "4s"), ("f64x2", "2d")]:
    seq(f"{shape}_add", f"fadd v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_sub", f"fsub v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_mul", f"fmul v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_div", f"fdiv v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_sqrt", f"fsqrt v0.{T}, v0.{T}")
    seq(f"{shape}_abs", f"fabs v0.{T}, v0.{T}")
    seq(f"{shape}_neg", f"fneg v0.{T}, v0.{T}")
    # FMIN/FMAX match wasm: NaN-propagating, -0 < +0.
    seq(f"{shape}_min", f"fmin v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_max", f"fmax v0.{T}, v0.{T}, v1.{T}")
    # pmin(a,b) = b<a ? b : a; pmax(a,b) = a<b ? b : a. fcmgt mask selects b.
    seq(f"{shape}_pmin",
        f"fcmgt v2.{T}, v0.{T}, v1.{T}", f"bsl v2.16b, v1.16b, v0.16b", "mov v0.16b, v2.16b")
    seq(f"{shape}_pmax",
        f"fcmgt v2.{T}, v1.{T}, v0.{T}", f"bsl v2.16b, v1.16b, v0.16b", "mov v0.16b, v2.16b")
    seq(f"{shape}_ceil", f"frintp v0.{T}, v0.{T}")
    seq(f"{shape}_floor", f"frintm v0.{T}, v0.{T}")
    seq(f"{shape}_trunc", f"frintz v0.{T}, v0.{T}")
    seq(f"{shape}_nearest", f"frintn v0.{T}, v0.{T}")
    seq(f"{shape}_eq", f"fcmeq v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_ne", f"fcmeq v0.{T}, v0.{T}, v1.{T}", "mvn v0.16b, v0.16b")
    seq(f"{shape}_lt", f"fcmgt v0.{T}, v1.{T}, v0.{T}")
    seq(f"{shape}_gt", f"fcmgt v0.{T}, v0.{T}, v1.{T}")
    seq(f"{shape}_le", f"fcmge v0.{T}, v1.{T}, v0.{T}")
    seq(f"{shape}_ge", f"fcmge v0.{T}, v0.{T}, v1.{T}")

# conversions
seq("i32x4_trunc_sat_f32x4_s", "fcvtzs v0.4s, v0.4s")
seq("i32x4_trunc_sat_f32x4_u", "fcvtzu v0.4s, v0.4s")
seq("f32x4_convert_i32x4_s", "scvtf v0.4s, v0.4s")
seq("f32x4_convert_i32x4_u", "ucvtf v0.4s, v0.4s")
# f64 → i32 with zeroed upper lanes: saturating double conversion composes.
seq("i32x4_trunc_sat_f64x2_s_zero", "fcvtzs v0.2d, v0.2d", "sqxtn v0.2s, v0.2d")
seq("i32x4_trunc_sat_f64x2_u_zero", "fcvtzu v0.2d, v0.2d", "uqxtn v0.2s, v0.2d")
seq("f64x2_convert_low_i32x4_s", "sshll v0.2d, v0.2s, #0", "scvtf v0.2d, v0.2d")
seq("f64x2_convert_low_i32x4_u", "ushll v0.2d, v0.2s, #0", "ucvtf v0.2d, v0.2d")
seq("f32x4_demote_f64x2_zero", "fcvtn v0.2s, v0.2d")
seq("f64x2_promote_low_f32x4", "fcvtl v0.2d, v0.2s")


# ---------------------------------------------------------------------------
# amd64 sequence table (SSE, x86-64-v2 baseline: SSE4.2 available). Lines are
# native Go/Plan9 asm: the Go assembler's x86 coverage is complete, so no
# WORD encoding is needed. Fixed registers: a in X0, b in X1, c in X2, int
# scalar in AX, result in X0 (vector) or AX (scalar). Plan9 operand order is
# reversed from Intel: OP src, dst.
# ---------------------------------------------------------------------------

X64 = {}

def x64(name, *lines):
    X64[name] = list(lines)

# ---- v128 logic ----
x64("v128_not", "PCMPEQL X3, X3", "PXOR X3, X0")
x64("v128_and", "PAND X1, X0")
x64("v128_andnot", "MOVOU X1, X3", "PANDN X0, X3", "MOVOU X3, X0")
x64("v128_or", "POR X1, X0")
x64("v128_xor", "PXOR X1, X0")
x64("v128_bitselect", "PAND X2, X0", "PANDN X1, X2", "POR X2, X0")
x64("v128_any_true",
    "PXOR X3, X3", "PCMPEQB X0, X3", "PMOVMSKB X3, AX",
    "CMPL AX, $0xffff", "SETNE AX", "MOVBLZX AX, AX")

# ---- integer arithmetic ----
for shape, suf in [("i8x16", "B"), ("i16x8", "W"), ("i32x4", "L"), ("i64x2", "Q")]:
    x64(f"{shape}_add", f"PADD{suf} X1, X0")
    x64(f"{shape}_sub", f"PSUB{suf} X1, X0")
    x64(f"{shape}_neg", "PXOR X3, X3", f"PSUB{suf} X0, X3", "MOVOU X3, X0")
    x64(f"{shape}_eq", f"PCMPEQ{suf} X1, X0")
    x64(f"{shape}_ne", f"PCMPEQ{suf} X1, X0", "PCMPEQL X3, X3", "PXOR X3, X0")
    x64(f"{shape}_gt_s", f"PCMPGT{suf} X1, X0")
    x64(f"{shape}_lt_s", "MOVOU X1, X3", f"PCMPGT{suf} X0, X3", "MOVOU X3, X0")
    # ge_s = !(b > a), le_s = !(a > b)
    x64(f"{shape}_ge_s",
        "MOVOU X1, X3", f"PCMPGT{suf} X0, X3", "PCMPEQL X4, X4", "PXOR X4, X3", "MOVOU X3, X0")
    x64(f"{shape}_le_s",
        f"PCMPGT{suf} X1, X0", "PCMPEQL X4, X4", "PXOR X4, X0")
x64("i16x8_mul", "PMULLW X1, X0")
x64("i32x4_mul", "PMULLD X1, X0")
x64("i8x16_abs", "PABSB X0, X0")
x64("i16x8_abs", "PABSW X0, X0")
x64("i32x4_abs", "PABSD X0, X0")
x64("i64x2_abs",
    "PXOR X3, X3", "PCMPGTQ X0, X3", "PXOR X3, X0", "PSUBQ X3, X0")

# unsigned min/max/compares (min/max then eq)
for shape, mn, mx, eq in [("i8x16", "PMINUB", "PMAXUB", "PCMPEQB"),
                          ("i16x8", "PMINUW", "PMAXUW", "PCMPEQW"),
                          ("i32x4", "PMINUD", "PMAXUD", "PCMPEQL")]:
    x64(f"{shape}_ge_u", "MOVOU X0, X3", f"{mx} X1, X3", f"{eq} X0, X3", "MOVOU X3, X0")
    x64(f"{shape}_le_u", "MOVOU X0, X3", f"{mn} X1, X3", f"{eq} X0, X3", "MOVOU X3, X0")
    x64(f"{shape}_lt_u",
        "MOVOU X0, X3", f"{mx} X1, X3", f"{eq} X0, X3",
        "PCMPEQL X4, X4", "PXOR X4, X3", "MOVOU X3, X0")
    x64(f"{shape}_gt_u",
        "MOVOU X0, X3", f"{mn} X1, X3", f"{eq} X0, X3",
        "PCMPEQL X4, X4", "PXOR X4, X3", "MOVOU X3, X0")
x64("i8x16_min_s", "PMINSB X1, X0")
x64("i8x16_min_u", "PMINUB X1, X0")
x64("i8x16_max_s", "PMAXSB X1, X0")
x64("i8x16_max_u", "PMAXUB X1, X0")
x64("i16x8_min_s", "PMINSW X1, X0")
x64("i16x8_min_u", "PMINUW X1, X0")
x64("i16x8_max_s", "PMAXSW X1, X0")
x64("i16x8_max_u", "PMAXUW X1, X0")
x64("i32x4_min_s", "PMINSD X1, X0")
x64("i32x4_min_u", "PMINUD X1, X0")
x64("i32x4_max_s", "PMAXSD X1, X0")
x64("i32x4_max_u", "PMAXUD X1, X0")

# saturating + average + q15mulr
x64("i8x16_add_sat_s", "PADDSB X1, X0")
x64("i8x16_add_sat_u", "PADDUSB X1, X0")
x64("i8x16_sub_sat_s", "PSUBSB X1, X0")
x64("i8x16_sub_sat_u", "PSUBUSB X1, X0")
x64("i16x8_add_sat_s", "PADDSW X1, X0")
x64("i16x8_add_sat_u", "PADDUSW X1, X0")
x64("i16x8_sub_sat_s", "PSUBSW X1, X0")
x64("i16x8_sub_sat_u", "PSUBUSW X1, X0")
x64("i8x16_avgr_u", "PAVGB X1, X0")
x64("i16x8_avgr_u", "PAVGW X1, X0")
# PMULHRSW computes the rounded Q15 product but wraps INT16_MIN*INT16_MIN
# to 0x8000 instead of saturating; flip exactly those lanes to 0x7fff.
x64("i16x8_q15mulr_sat_s",
    "MOVOU ·simdConstI16Min(SB), X3",
    "MOVOU X0, X4", "PCMPEQW X3, X4",
    "MOVOU X1, X5", "PCMPEQW X3, X5",
    "PAND X5, X4",
    "PMULHRSW X1, X0",
    "PXOR X4, X0")

# popcnt via nibble LUT
x64("i8x16_popcnt",
    "MOVOU ·simdConstPopLUT(SB), X3",
    "MOVOU ·simdConstNib(SB), X4",
    "MOVOU X0, X5",
    "PAND X4, X0",
    "PSRLW $4, X5",
    "PAND X4, X5",
    "MOVOU X3, X6",
    "PSHUFB X0, X6",
    "PSHUFB X5, X3",
    "PADDB X6, X3",
    "MOVOU X3, X0")

# shifts (dynamic count; wasm masks by lane width)
x64("i16x8_shl", "ANDL $15, AX", "MOVQ AX, X3", "PSLLW X3, X0")
x64("i16x8_shr_s", "ANDL $15, AX", "MOVQ AX, X3", "PSRAW X3, X0")
x64("i16x8_shr_u", "ANDL $15, AX", "MOVQ AX, X3", "PSRLW X3, X0")
x64("i32x4_shl", "ANDL $31, AX", "MOVQ AX, X3", "PSLLL X3, X0")
x64("i32x4_shr_s", "ANDL $31, AX", "MOVQ AX, X3", "PSRAL X3, X0")
x64("i32x4_shr_u", "ANDL $31, AX", "MOVQ AX, X3", "PSRLL X3, X0")
x64("i64x2_shl", "ANDL $63, AX", "MOVQ AX, X3", "PSLLQ X3, X0")
x64("i64x2_shr_u", "ANDL $63, AX", "MOVQ AX, X3", "PSRLQ X3, X0")
# i8 shifts: widen to 16-bit halves, shift, repack.
x64("i8x16_shl",
    "ANDL $7, AX", "MOVQ AX, X3", "MOVL AX, CX",
    "MOVL $0xff, AX", "SHLL CX, AX", "ANDL $0xff, AX",
    "IMULL $0x01010101, AX", "MOVQ AX, X4", "PSHUFD $0, X4, X4",
    "PSLLW X3, X0", "PAND X4, X0")
x64("i8x16_shr_u",
    "ANDL $7, AX", "MOVQ AX, X3", "MOVL AX, CX",
    "MOVL $0xff, AX", "SHRL CX, AX",
    "IMULL $0x01010101, AX", "MOVQ AX, X4", "PSHUFD $0, X4, X4",
    "PSRLW X3, X0", "PAND X4, X0")
x64("i8x16_shr_s",
    "ANDL $7, AX", "ADDL $8, AX", "MOVQ AX, X3",
    "MOVOU X0, X5",
    "PUNPCKLBW X0, X0", "PSRAW X3, X0",
    "PUNPCKHBW X5, X5", "PSRAW X3, X5",
    "PACKSSWB X5, X0")

# all_true / bitmask
for shape, eq in [("i8x16", "PCMPEQB"), ("i16x8", "PCMPEQW"),
                  ("i32x4", "PCMPEQL"), ("i64x2", "PCMPEQQ")]:
    x64(f"{shape}_all_true",
        "PXOR X3, X3", f"{eq} X0, X3", "PMOVMSKB X3, AX",
        "TESTL AX, AX", "SETEQ AX", "MOVBLZX AX, AX")
x64("i8x16_bitmask", "PMOVMSKB X0, AX")
x64("i16x8_bitmask", "PACKSSWB X0, X0", "PMOVMSKB X0, AX", "ANDL $0xff, AX")
x64("i32x4_bitmask", "MOVMSKPS X0, AX")
x64("i64x2_bitmask", "MOVMSKPD X0, AX")

# narrow / extend / extmul / extadd / dot
x64("i8x16_narrow_i16x8_s", "PACKSSWB X1, X0")
x64("i8x16_narrow_i16x8_u", "PACKUSWB X1, X0")
x64("i16x8_narrow_i32x4_s", "PACKSSLW X1, X0")
x64("i16x8_narrow_i32x4_u", "PACKUSDW X1, X0")
for dst, src, sx, zx in [("i16x8", "i8x16", "PMOVSXBW", "PMOVZXBW"),
                         ("i32x4", "i16x8", "PMOVSXWD", "PMOVZXWD"),
                         ("i64x2", "i32x4", "PMOVSXDQ", "PMOVZXDQ")]:
    x64(f"{dst}_extend_low_{src}_s", f"{sx} X0, X0")
    x64(f"{dst}_extend_low_{src}_u", f"{zx} X0, X0")
    x64(f"{dst}_extend_high_{src}_s", "PSRLO $8, X0", f"{sx} X0, X0")
    x64(f"{dst}_extend_high_{src}_u", "PSRLO $8, X0", f"{zx} X0, X0")
x64("i32x4_dot_i16x8_s", "PMADDWL X1, X0")
x64("i32x4_extadd_pairwise_i16x8_s",
    "MOVOU ·simdConstOnes16(SB), X3", "PMADDWL X3, X0")
x64("i32x4_extadd_pairwise_i16x8_u",
    "MOVOU X0, X3", "PSRLL $16, X3",
    "PSLLL $16, X0", "PSRLL $16, X0", "PADDD X3, X0")
x64("i16x8_extadd_pairwise_i8x16_s",
    "MOVOU ·simdConstOnes8(SB), X3", "PMADDUBSW X0, X3", "MOVOU X3, X0")
x64("i16x8_extadd_pairwise_i8x16_u",
    "MOVOU ·simdConstOnes8(SB), X3", "PMADDUBSW X3, X0")
# extmul via extend-low/high then PMULLW/PMULLD
x64("i16x8_extmul_low_i8x16_s", "PMOVSXBW X0, X0", "PMOVSXBW X1, X1", "PMULLW X1, X0")
x64("i16x8_extmul_low_i8x16_u", "PMOVZXBW X0, X0", "PMOVZXBW X1, X1", "PMULLW X1, X0")
x64("i16x8_extmul_high_i8x16_s",
    "PSRLO $8, X0", "PSRLO $8, X1", "PMOVSXBW X0, X0", "PMOVSXBW X1, X1", "PMULLW X1, X0")
x64("i16x8_extmul_high_i8x16_u",
    "PSRLO $8, X0", "PSRLO $8, X1", "PMOVZXBW X0, X0", "PMOVZXBW X1, X1", "PMULLW X1, X0")
x64("i32x4_extmul_low_i16x8_s", "PMOVSXWD X0, X0", "PMOVSXWD X1, X1", "PMULLD X1, X0")
x64("i32x4_extmul_low_i16x8_u", "PMOVZXWD X0, X0", "PMOVZXWD X1, X1", "PMULLD X1, X0")
x64("i32x4_extmul_high_i16x8_s",
    "PSRLO $8, X0", "PSRLO $8, X1", "PMOVSXWD X0, X0", "PMOVSXWD X1, X1", "PMULLD X1, X0")
x64("i32x4_extmul_high_i16x8_u",
    "PSRLO $8, X0", "PSRLO $8, X1", "PMOVZXWD X0, X0", "PMOVZXWD X1, X1", "PMULLD X1, X0")
x64("i64x2_extmul_low_i32x4_s",
    "PSHUFD $0x50, X0, X0", "PSHUFD $0x50, X1, X1", "PMULDQ X1, X0")
x64("i64x2_extmul_low_i32x4_u",
    "PSHUFD $0x50, X0, X0", "PSHUFD $0x50, X1, X1", "PMULULQ X1, X0")
x64("i64x2_extmul_high_i32x4_s",
    "PSHUFD $0xfa, X0, X0", "PSHUFD $0xfa, X1, X1", "PMULDQ X1, X0")
x64("i64x2_extmul_high_i32x4_u",
    "PSHUFD $0xfa, X0, X0", "PSHUFD $0xfa, X1, X1", "PMULULQ X1, X0")

# swizzle / shuffle / splats
x64("i8x16_swizzle",
    "MOVOU ·simdConst70(SB), X3", "PADDUSB X3, X1", "PSHUFB X1, X0")
x64("i8x16_shuffle",
    "MOVOU ·simdConst70(SB), X3",
    "MOVOU X2, X4",
    "PADDUSB X3, X4",
    "PSHUFB X4, X0",
    "MOVOU ·simdConst16(SB), X5",
    "PSUBB X5, X2",
    "PADDUSB X3, X2",
    "PSHUFB X2, X1",
    "POR X1, X0")
x64("i8x16_splat",
    "MOVQ AX, X0", "PXOR X3, X3", "PSHUFB X3, X0")
x64("i16x8_splat",
    "MOVQ AX, X0", "PSHUFLW $0, X0, X0", "PSHUFD $0, X0, X0")
x64("i32x4_splat", "MOVQ AX, X0", "PSHUFD $0, X0, X0")
x64("i64x2_splat", "MOVQ AX, X0", "PSHUFD $0x44, X0, X0")
x64("f32x4_splat", "SHUFPS $0, X0, X0")   # arg preloaded into X0 low
x64("f64x2_splat", "UNPCKLPD X0, X0")     # arg preloaded into X0 low

# ---- floats ----
for shape, S in [("f32x4", "PS"), ("f64x2", "PD")]:
    x64(f"{shape}_add", f"ADD{S} X1, X0")
    x64(f"{shape}_sub", f"SUB{S} X1, X0")
    x64(f"{shape}_mul", f"MUL{S} X1, X0")
    x64(f"{shape}_div", f"DIV{S} X1, X0")
    x64(f"{shape}_sqrt", f"SQRT{S} X0, X0")
    # pmin/pmax map exactly onto Intel MIN/MAX with swapped operands
    # (ties and NaN resolve to the second source = a).
    x64(f"{shape}_pmin", "MOVOU X1, X3", f"MIN{S} X0, X3", "MOVOU X3, X0")
    x64(f"{shape}_pmax", "MOVOU X1, X3", f"MAX{S} X0, X3", "MOVOU X3, X0")
    x64(f"{shape}_eq", f"CMP{S} X1, X0, $0")
    x64(f"{shape}_ne", f"CMP{S} X1, X0, $4")
    x64(f"{shape}_lt", f"CMP{S} X1, X0, $1")
    x64(f"{shape}_le", f"CMP{S} X1, X0, $2")
    x64(f"{shape}_gt", "MOVOU X1, X3", f"CMP{S} X0, X3, $1", "MOVOU X3, X0")
    x64(f"{shape}_ge", "MOVOU X1, X3", f"CMP{S} X0, X3, $2", "MOVOU X3, X0")
    # wasm min/max: NaN-propagating, -0 vs +0 ordered. The classic two-
    # sided sequence: both operand orders, then merge (OR for min keeps
    # any -0 and any NaN; for max the XOR/SUB pair achieves the AND-
    # merge of signs), then force lanes that compared unordered to NaN.
    x64(f"{shape}_min",
        "MOVOU X0, X3", f"MIN{S} X1, X3",
        "MOVOU X1, X4", f"MIN{S} X0, X4",
        f"OR{S} X4, X3",
        "MOVOU X3, X5", f"CMP{S} X5, X5, $3",
        f"OR{S} X5, X3",
        "MOVOU X3, X0")
    x64(f"{shape}_max",
        "MOVOU X0, X3", f"MAX{S} X1, X3",
        "MOVOU X1, X4", f"MAX{S} X0, X4",
        "MOVOU X3, X5", f"XOR{S} X4, X5",
        f"OR{S} X5, X3",
        f"SUB{S} X5, X3",
        "MOVOU X3, X5", f"CMP{S} X5, X5, $3",
        f"OR{S} X5, X3",
        "MOVOU X3, X0")
x64("f32x4_ceil", "ROUNDPS $2, X0, X0")
x64("f32x4_floor", "ROUNDPS $1, X0, X0")
x64("f32x4_trunc", "ROUNDPS $3, X0, X0")
x64("f32x4_nearest", "ROUNDPS $0, X0, X0")
x64("f64x2_ceil", "ROUNDPD $2, X0, X0")
x64("f64x2_floor", "ROUNDPD $1, X0, X0")
x64("f64x2_trunc", "ROUNDPD $3, X0, X0")
x64("f64x2_nearest", "ROUNDPD $0, X0, X0")
x64("f32x4_abs", "MOVOU ·simdConstAbs32(SB), X3", "ANDPS X3, X0")
x64("f32x4_neg", "MOVOU ·simdConstSign32(SB), X3", "XORPS X3, X0")
x64("f64x2_abs", "MOVOU ·simdConstAbs64(SB), X3", "ANDPD X3, X0")
x64("f64x2_neg", "MOVOU ·simdConstSign64(SB), X3", "XORPD X3, X0")

# conversions
x64("f32x4_convert_i32x4_s", "CVTPL2PS X0, X0")
x64("f64x2_convert_low_i32x4_s", "CVTPL2PD X0, X0")
x64("f32x4_demote_f64x2_zero", "CVTPD2PS X0, X0")
x64("f64x2_promote_low_f32x4", "CVTPS2PD X0, X0")
# trunc_sat_f32x4_s: CVTTPS2PL yields 0x80000000 for NaN/overflow; zero the
# NaN lanes first (a != a), then flip positive-overflow lanes (a >= 2^31)
# from INT_MIN to INT_MAX.
x64("i32x4_trunc_sat_f32x4_s",
    "MOVOU X0, X3", "CMPPS X3, X3, $7",
    "ANDPS X3, X0",
    "MOVOU ·simdConst2p31f(SB), X4",
    "MOVOU X0, X5", "CMPPS X4, X5, $5",
    "CVTTPS2PL X0, X0",
    "PXOR X5, X0")
# trunc_sat_f32x4_u: do the low half (< 2^31) with the signed converter, the
# high half by biasing down 2^31, converting, and adding 2^31 back; negative
# and NaN lanes clamp to 0, >= 2^32 saturates to all-ones.
x64("i32x4_trunc_sat_f32x4_u",
    "PXOR X3, X3", f"MAXPS X3, X0",
    "MOVOU ·simdConst2p31f(SB), X4",
    "MOVOU X0, X5", f"SUBPS X4, X5",
    "MOVOU X5, X6", "CMPPS X4, X6, $5",
    "CVTTPS2PL X5, X5",
    "PXOR X6, X5",
    "PXOR X7, X7", "PMAXSD X7, X5",
    "CVTTPS2PL X0, X0",
    "PADDD X5, X0")
x64("i32x4_trunc_sat_f64x2_s_zero",
    "MOVOU X0, X3", "CMPPD X3, X3, $7",
    "ANDPD X3, X0",
    "MOVOU ·simdConst2p31d(SB), X4",
    "MINPD X4, X0",
    "CVTTPD2PL X0, X0")
x64("i32x4_trunc_sat_f64x2_u_zero",
    "PXOR X3, X3", "MAXPD X3, X0",
    "MOVOU ·simdConstUMaxd(SB), X4",
    "MINPD X4, X0",
    "ROUNDPD $3, X0, X0",
    "MOVOU ·simdConstMagicd(SB), X4",
    "ADDPD X4, X0",
    "SHUFPS $0x88, X3, X0")
# convert_u: split into high/low 16-bit halves, convert each exactly, then
# scale-add (the classic 65536*hi + lo recombination).
x64("f32x4_convert_i32x4_u",
    "MOVOU X0, X3",
    "PSRLL $16, X3",
    "PSLLL $16, X0", "PSRLL $16, X0",
    "CVTPL2PS X0, X0",
    "CVTPL2PS X3, X3",
    "MOVOU ·simdConst65536f(SB), X4",
    "MULPS X4, X3",
    "ADDPS X3, X0")
x64("f64x2_convert_low_i32x4_u",
    "MOVOU ·simdConstMagicHi(SB), X3",
    "PUNPCKLLQ X3, X0",
    "MOVOU ·simdConstMagicd(SB), X4",
    "SUBPD X4, X0")

X64_CONSTS = {
    "simdConstPopLUT": bytes([0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4]),
    "simdConstNib": bytes([0x0f]*16),
    "simdConstOnes16": (1).to_bytes(2, "little")*8,
    "simdConstOnes8": bytes([1]*16),
    "simdConst70": bytes([0x70]*16),
    "simdConst16": bytes([0x10]*16),
    "simdConstAbs32": (0x7fffffff).to_bytes(4, "little")*4,
    "simdConstSign32": (0x80000000).to_bytes(4, "little")*4,
    "simdConstAbs64": (0x7fffffffffffffff).to_bytes(8, "little")*2,
    "simdConstSign64": (0x8000000000000000).to_bytes(8, "little")*2,
    "simdConst2p31f": (0x4f000000).to_bytes(4, "little")*4,
    "simdConst2p31d": (0x41dfffffffc00000).to_bytes(8, "little")*2,   # 2147483647.0
    "simdConstUMaxd": (0x41efffffffe00000).to_bytes(8, "little")*2,   # 4294967295.0
    "simdConstMagicd": (0x4330000000000000).to_bytes(8, "little")*2,  # 2^52
    "simdConstMagicHi": (0x43300000).to_bytes(4, "little")*4,
    "simdConst65536f": (0x47800000).to_bytes(4, "little")*4,
    "simdConstI16Min": (0x8000).to_bytes(2, "little")*8,
}

# ---------------------------------------------------------------------------
# Signature parsing.
# ---------------------------------------------------------------------------

SIG_RE = re.compile(r"func (simd_\w+?)_scalar\((.*?)\)\s*(?:\(?([^{)]*?)\)?)?\s*\{", re.S)

def parse_sigs(path):
    src = open(path).read()
    sigs = {}
    for m in re.finditer(r"func (simd_\w+?)_scalar\(([^)]*)\)\s*([^\{]*)\{", src):
        name, params, ret = m.group(1), m.group(2).strip(), m.group(3).strip()
        sigs[name] = (params, ret)
    return sigs

def param_kinds(params):
    # e.g. "a, b [2]uint64" / "a [2]uint64, s int32" / "x float32"
    kinds = []
    for group in params.split(","):
        group = group.strip()
        if not group:
            continue
        parts = group.split()
        if len(parts) == 1:
            kinds.append((parts[0], None))  # type filled by next group
        else:
            typ = " ".join(parts[1:])
            for i in range(len(kinds) - 1, -1, -1):
                if kinds[i][1] is None:
                    kinds[i] = (kinds[i][0], typ)
                else:
                    break
            kinds.append((parts[0], typ))
    return kinds

def size_of(typ):
    return {"[2]uint64": 16, "int32": 4, "int64": 8, "uint32": 4, "float32": 4, "float64": 8}[typ]

def align_of(typ):
    return {"[2]uint64": 8, "int32": 4, "int64": 8, "uint32": 4, "float32": 4, "float64": 8}[typ]

# ---------------------------------------------------------------------------
# Emission.
# ---------------------------------------------------------------------------

def encode_gas(lines_by_key):
    """Assemble every distinct GAS line once; return line → uint32 word."""
    distinct = sorted(set(l for lines in lines_by_key.values() for l in lines if not l.startswith("go:")))
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "e.s")
        obj = os.path.join(td, "e.o")
        with open(src, "w") as f:
            f.write(".text\n")
            for l in distinct:
                f.write(l + "\n")
        subprocess.run([CLANG, "--target=aarch64-unknown-linux-gnu", "-c", src, "-o", obj], check=True)
        out = subprocess.run([OBJDUMP, "-d", obj], check=True, capture_output=True, text=True).stdout
    words = []
    for line in out.splitlines():
        m = re.match(r"\s*[0-9a-f]+:\s+([0-9a-f]{8})\s", line)
        if m:
            words.append(int(m.group(1), 16))
    if len(words) != len(distinct):
        sys.exit(f"encode mismatch: {len(words)} words for {len(distinct)} lines")
    return dict(zip(distinct, words))

def emit_asm_file(path, header_lines, consts, bodies):
    out = list(header_lines)
    for name, byts in consts:
        out.append(f"GLOBL \u00b7{name}(SB), RODATA|NOPTR, $16")
        for off in (0, 8):
            v = int.from_bytes(bytes(byts[off:off+8]), "little")
            out.append(f"DATA \u00b7{name}+{off}(SB)/8, $0x{v:016x}")
        out.append("")
    out.extend(bodies)
    open(path, "w").write("\n".join(out))


def stack_layout(kinds, ret):
    off = 0
    slots = []
    for pname, typ in kinds:
        a = align_of(typ)
        off = (off + a - 1) & ~(a - 1)
        slots.append((pname, typ, off))
        off += size_of(typ)
    ra = align_of(ret)
    off = (off + ra - 1) & ~(ra - 1)
    return slots, off, off + size_of(ret)


def arm64_body(name, sigs):
    params, ret = sigs[name]
    slots, retoff, total = stack_layout(param_kinds(params), ret)
    lines = [f"TEXT \u00b7{name}(SB), NOSPLIT|NOFRAME, $0-{total}"]
    vreg = 0
    for pname, typ, off in slots:
        if typ == "[2]uint64":
            lines.append(f"\tFMOVQ {pname}+{off}(FP), F{vreg}")
            vreg += 1
        elif typ in ("int32", "uint32"):
            lines.append(f"\tMOVWU {pname}+{off}(FP), R0")
        elif typ == "int64":
            lines.append(f"\tMOVD {pname}+{off}(FP), R0")
        elif typ == "float32":
            lines.append(f"\tFMOVS {pname}+{off}(FP), F0")
        elif typ == "float64":
            lines.append(f"\tFMOVD {pname}+{off}(FP), F0")
    return lines, retoff


def amd64_body(name, sigs):
    params, ret = sigs[name]
    slots, retoff, total = stack_layout(param_kinds(params), ret)
    lines = [f"TEXT \u00b7{name}(SB), NOSPLIT, $0-{total}"]
    xreg = 0
    for pname, typ, off in slots:
        if typ == "[2]uint64":
            lines.append(f"\tMOVOU {pname}+{off}(FP), X{xreg}")
            xreg += 1
        elif typ in ("int32", "uint32"):
            lines.append(f"\tMOVL {pname}+{off}(FP), AX")
        elif typ == "int64":
            lines.append(f"\tMOVQ {pname}+{off}(FP), AX")
        elif typ == "float32":
            lines.append(f"\tMOVSS {pname}+{off}(FP), X0")
        elif typ == "float64":
            lines.append(f"\tMOVSD {pname}+{off}(FP), X0")
    return lines, retoff


def emit_scalar_subset(path, tag, sigs, names):
    """Emits the _scalar bodies for `names` only, for an asm arch."""
    src = open(f"{HELPERS}/simd_scalar.go").read()
    chunks = re.split(r"\n(?=//go:noinline\nfunc |func )", src)
    keep = []
    for ch in chunks:
        m = re.search(r"func (\w+)\(", ch)
        if not m:
            continue
        fn = m.group(1)
        # Shared utilities (converters, saturation, NaN rules) are needed by
        # whichever bodies remain; keep them all — they are small.
        if fn.startswith("simd_"):
            if fn.removesuffix("_scalar") in names:
                keep.append(ch)
            continue
        keep.append(ch)
    hdr = ("// Code generated by tools/gen-simd-asm/gen.py; DO NOT EDIT.\n"
           "//\n"
           "// The scalar bodies this arch still needs: every op its assembly\n"
           "// does not cover, plus the shared lane/saturation utilities. The\n"
           "// full reference set lives in simd_scalar.go, which is tagged out\n"
           "// of the asm arches to keep generated Go small.\n"
           "\n"
           f"//go:build {tag}\n"
           "\n"
           "package helpers\n"
           "\n"
           "import \"math\"\n"
           "\n"
           "import \"math/bits\"\n"
           "\n"
           "var _ = bits.OnesCount8\n"
           "var _ = math.Sqrt\n"
           "\n")
    open(path, "w").write(hdr + "\n".join(keep))


def emit_decls(path, tag, sigs, covered):
    d = ["// Code generated by tools/gen-simd-asm/gen.py; DO NOT EDIT.",
         "",
         f"//go:build {tag}",
         "",
         "package helpers",
         ""]
    for name in sorted(covered):
        params, ret = sigs[name]
        d.append(f"func {name}({params}) {ret}")
    d.append("")
    d.append("// Ops without a native body on this arch use the scalar reference.")
    for name in sorted(set(sigs) - covered):
        params, ret = sigs[name]
        args = ", ".join(p for p, _ in param_kinds(params))
        d.append(f"func {name}({params}) {ret} {{ return {name}_scalar({args}) }}")
    open(path, "w").write("\n".join(d) + "\n")




def emit_pair_matrix_test(path, sigs, covered):
    # The pair-wrapper battery: exercises every lowercase simd_p_*
    # wrapper (pure on every arch) against the underlying simd_* op
    # with exact equality — the wrapper marshals [2]uint64 halves, so
    # any argument-order or half-swap bug shows immediately. Untagged:
    # this is what gives the pure scalar bodies coverage on plain CI
    # builds, where the asm decls are not even compiled.
    t = ["// Code generated by tools/gen-simd-asm/gen.py; DO NOT EDIT.",
         "",
         "package helpers",
         "",
         "import (",
         '\t"math"',
         '\t"testing"',
         ")",
         "",
         "var _ = math.Float32bits",
         ""]
    cats = {"vv_v": [], "v_v": [], "vvv_v": [], "vs_v": [], "v_i32": [],
            "v_i64": [], "s32_v": [], "s64_v": [], "f32_v": [], "f64_v": []}
    for name in sorted(covered):
        params, ret = sigs[name]
        ks = [k for _, k in param_kinds(params)]
        if ks == ["[2]uint64", "[2]uint64"] and ret == "[2]uint64":
            cats["vv_v"].append(name)
        elif ks == ["[2]uint64"] and ret == "[2]uint64":
            cats["v_v"].append(name)
        elif ks == ["[2]uint64", "[2]uint64", "[2]uint64"]:
            cats["vvv_v"].append(name)
        elif ks == ["[2]uint64", "int32"] and ret == "[2]uint64":
            cats["vs_v"].append(name)
        elif ks == ["[2]uint64"] and ret == "int32":
            cats["v_i32"].append(name)
        elif ks == ["[2]uint64"] and ret == "int64":
            cats["v_i64"].append(name)
        elif ks == ["int32"]:
            cats["s32_v"].append(name)
        elif ks == ["int64"]:
            cats["s64_v"].append(name)
        elif ks == ["float32"]:
            cats["f32_v"].append(name)
        elif ks == ["float64"]:
            cats["f64_v"].append(name)
        elif ks == ["[2]uint64", "int32"] and ret in ("int32", "int64", "uint32", "float32", "float64"):
            cats.setdefault("vs_s:" + ret, []).append(name)
        else:
            continue  # exotic shapes (shuffle consts, lane replace) skip
    def pname(n):
        return "simd_p_" + n[len("simd_"):]
    t.append("var simdPairCorpus = [][2]uint64{")
    t.append("\t{0, 0},")
    t.append("\t{^uint64(0), ^uint64(0)},")
    t.append("\t{0x8000000080000000, 0x7fc00000ff800001},")
    t.append("\t{0x0102030405060708, 0x090a0b0c0d0e0f10},")
    t.append("\t{0x7fff7fff7fff7fff, 0x8080808080808080},")
    t.append("}")
    t.append("")
    t.append("func TestSimdPairWrappers(t *testing.T) {")
    t.append("\tfor _, a := range simdPairCorpus {")
    t.append("\t\tfor _, b := range simdPairCorpus {")
    for n in cats["vv_v"]:
        t.append(f'\t\t\tif l, h := {pname(n)}(a[0], a[1], b[0], b[1]); [2]uint64{{l, h}} != {n}(a, b) {{')
        t.append(f'\t\t\t\tt.Fatalf("{pname(n)}(%x, %x)", a, b)')
        t.append("\t\t\t}")
    for n in cats["vvv_v"]:
        t.append(f'\t\t\tif l, h := {pname(n)}(a[0], a[1], b[0], b[1], a[0], a[1]); [2]uint64{{l, h}} != {n}(a, b, a) {{')
        t.append(f'\t\t\t\tt.Fatalf("{pname(n)}(%x, %x)", a, b)')
        t.append("\t\t\t}")
    t.append("\t\t}")
    for n in cats["v_v"]:
        t.append(f'\t\tif l, h := {pname(n)}(a[0], a[1]); [2]uint64{{l, h}} != {n}(a) {{')
        t.append(f'\t\t\tt.Fatalf("{pname(n)}(%x)", a)')
        t.append("\t\t}")
    for n in cats["v_i32"]:
        t.append(f'\t\tif {pname(n)}(a[0], a[1]) != {n}(a) {{')
        t.append(f'\t\t\tt.Fatalf("{pname(n)}(%x)", a)')
        t.append("\t\t}")
    for n in cats["v_i64"]:
        t.append(f'\t\tif {pname(n)}(a[0], a[1]) != {n}(a) {{')
        t.append(f'\t\t\tt.Fatalf("{pname(n)}(%x)", a)')
        t.append("\t\t}")
    t.append("\t\tfor _, s := range []int32{0, 1} {")
    for key in sorted(k for k in cats if k.startswith("vs_s:")):
        ret = key.split(":")[1]
        for n in cats[key]:
            if ret == "float32":
                cmp = f"math.Float32bits({pname(n)}(a[0], a[1], s)) != math.Float32bits({n}(a, s))"
            elif ret == "float64":
                cmp = f"math.Float64bits({pname(n)}(a[0], a[1], s)) != math.Float64bits({n}(a, s))"
            else:
                cmp = f"{pname(n)}(a[0], a[1], s) != {n}(a, s)"
            t.append(f"\t\t\tif {cmp} {{")
            t.append(f'\t\t\t\tt.Fatalf("{pname(n)}(%x, %d)", a, s)')
            t.append("\t\t\t}")
    t.append("\t\t}")
    t.append("\t\tfor _, s := range []int32{0, 1, 7, 31, 32, 63, 64, -1} {")
    for n in cats["vs_v"]:
        t.append(f'\t\t\tif l, h := {pname(n)}(a[0], a[1], s); [2]uint64{{l, h}} != {n}(a, s) {{')
        t.append(f'\t\t\t\tt.Fatalf("{pname(n)}(%x, %d)", a, s)')
        t.append("\t\t\t}")
    t.append("\t\t}")
    t.append("\t}")
    t.append("\tfor _, s := range []int32{0, 1, -1, 0x7fffffff, -0x80000000} {")
    for n in cats["s32_v"]:
        t.append(f'\t\tif l, h := {pname(n)}(s); [2]uint64{{l, h}} != {n}(s) {{')
        t.append(f'\t\t\tt.Fatalf("{pname(n)}(%d)", s)')
        t.append("\t\t}")
    t.append("\t}")
    t.append("\tfor _, s := range []int64{0, 1, -1, 1 << 62} {")
    for n in cats["s64_v"]:
        t.append(f'\t\tif l, h := {pname(n)}(s); [2]uint64{{l, h}} != {n}(s) {{')
        t.append(f'\t\t\tt.Fatalf("{pname(n)}(%d)", s)')
        t.append("\t\t}")
    t.append("\t}")
    t.append("\tfor _, f := range []float32{0, 1.5, -2.25e10} {")
    for n in cats["f32_v"]:
        t.append(f'\t\tif l, h := {pname(n)}(f); [2]uint64{{l, h}} != {n}(f) {{')
        t.append(f'\t\t\tt.Fatalf("{pname(n)}(%v)", f)')
        t.append("\t\t}")
    t.append("\t}")
    t.append("\tfor _, f := range []float64{0, 1.5, -2.25e10} {")
    for n in cats["f64_v"]:
        t.append(f'\t\tif l, h := {pname(n)}(f); [2]uint64{{l, h}} != {n}(f) {{')
        t.append(f'\t\t\tt.Fatalf("{pname(n)}(%v)", f)')
        t.append("\t\t}")
    t.append("\t}")
    t.append("}")
    with open(path, "w") as f:
        f.write("\n".join(t) + "\n")


def emit_matrix_test(path, tag, sigs, covered, minmax_tolerant):
    t = ["// Code generated by tools/gen-simd-asm/gen.py; DO NOT EDIT.",
         "",
         f"//go:build {tag}",
         "",
         "package helpers",
         "",
         "import (",
         '\t"math"',
         '\t"math/rand"',
         '\t"testing"',
         ")",
         "",
         "// corpus: edge-case lane patterns plus seeded random vectors. The asm",
         "// bodies must agree with the scalar reference on all of them; see",
         "// simdEq for the one sanctioned divergence (which NaN an op returns).",
         "var simdAsmCorpus = func() [][2]uint64 {",
         "\tvs := [][2]uint64{",
         "\t\t{0, 0},",
         "\t\t{^uint64(0), ^uint64(0)},",
         "\t\t{0x8080808080808080, 0x8080808080808080},",
         "\t\t{0x8000800080008000, 0x8000800080008000},",
         "\t\t{0x8000000080000000, 0x8000000080000000},",
         "\t\t{0x8000000000000000, 0x8000000000000000},",
         "\t\t{0x7f7f7f7f7f7f7f7f, 0x0101010101010101},",
         "\t\t{0x7fff7fff7fff7fff, 0xffffffffffffffff},",
         "\t\t{0x7fffffff7fffffff, 0x0000000100000001},",
         "\t\t{0x7fc000007fc00000, 0xffc00000ff800001}, // f32 NaNs / -inf+payload",
         "\t\t{0x7ff8000000000000, 0xfff0000000000001}, // f64 NaN / sNaN",
         "\t\t{0x3f8000004048f5c3, 0xc248f5c300000000}, // f32 1.0, pi-ish, -50.24, +0",
         "\t\t{0x4f80000041dfffff, 0xcf000000c1dfffff}, // f32 2^32, near-2^31 bounds",
         "\t\t{0x8000000000000000, 0x0000000000000000}, // f64 -0, +0",
         "\t\t{0x41dfffffffc00000, 0x43f0000000000000}, // f64 2^31-1, 2^64",
         "\t\t{0x0102030405060708, 0x090a0b0c0d0e0f10},",
         "\t\t{0x1011121380402010, 0xfefdfcfb00ff7f80}, // swizzle/shuffle indices",
         "\t}",
         "\tr := rand.New(rand.NewSource(1))",
         "\tfor i := 0; i < 32; i++ {",
         "\t\tvs = append(vs, [2]uint64{r.Uint64(), r.Uint64()})",
         "\t}",
         "\treturn vs",
         "}()",
         "",
         "var simdAsmShifts = []int32{0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 65, -1}",
         ""]
    cats = {"vv_v": [], "v_v": [], "vvv_v": [], "vs_v": [], "v_i32": [],
            "v_i64": [], "s32_v": [], "s64_v": [], "f32_v": [], "f64_v": []}
    for name in sorted(covered):
        params, ret = sigs[name]
        ks = [k for _, k in param_kinds(params)]
        if ks == ["[2]uint64", "[2]uint64"] and ret == "[2]uint64":
            cats["vv_v"].append(name)
        elif ks == ["[2]uint64"] and ret == "[2]uint64":
            cats["v_v"].append(name)
        elif ks == ["[2]uint64", "[2]uint64", "[2]uint64"]:
            cats["vvv_v"].append(name)
        elif ks == ["[2]uint64", "int32"] and ret == "[2]uint64":
            cats["vs_v"].append(name)
        elif ks == ["[2]uint64"] and ret == "int32":
            cats["v_i32"].append(name)
        elif ks == ["[2]uint64"] and ret == "int64":
            cats["v_i64"].append(name)
        elif ks == ["int32"]:
            cats["s32_v"].append(name)
        elif ks == ["int64"]:
            cats["s64_v"].append(name)
        elif ks == ["float32"]:
            cats["f32_v"].append(name)
        elif ks == ["float64"]:
            cats["f64_v"].append(name)
        else:
            sys.exit(f"uncategorized covered op {name}: {ks} -> {ret}")
    def table(cat, sig):
        t.append(f"var simdAsm_{cat} = map[string][2]func{sig}{{")
        for n in cats[cat]:
            t.append(f'\t"{n}": {{{n}, {n}_scalar}},')
        t.append("}")
        t.append("")
    table("vv_v", "([2]uint64, [2]uint64) [2]uint64")
    table("v_v", "([2]uint64) [2]uint64")
    table("vvv_v", "([2]uint64, [2]uint64, [2]uint64) [2]uint64")
    table("vs_v", "([2]uint64, int32) [2]uint64")
    table("v_i32", "([2]uint64) int32")
    table("v_i64", "([2]uint64) int64")
    table("s32_v", "(int32) [2]uint64")
    table("s64_v", "(int64) [2]uint64")
    table("f32_v", "(float32) [2]uint64")
    table("f64_v", "(float64) [2]uint64")
    if minmax_tolerant:
        extra32 = ', "simd_f32x4_min", "simd_f32x4_max"'
        extra64 = ', "simd_f64x2_min", "simd_f64x2_max"'
        why = ("// On this arch min/max are two-sided compare sequences whose NaN\n"
               "// lanes come out all-ones rather than the scalar reference's\n"
               "// propagated payload — both are conforming arithmetic NaNs.")
    else:
        extra32 = ""
        extra64 = ""
        why = ""
    cases32 = '"simd_f32x4_add", "simd_f32x4_sub", "simd_f32x4_mul", "simd_f32x4_div"' + extra32
    cases64 = '"simd_f64x2_add", "simd_f64x2_sub", "simd_f64x2_mul", "simd_f64x2_div"' + extra64
    t.append("""// Which NaN an operation propagates when several operands are NaN is
// nondeterministic in wasm, and for plain float arithmetic it depends on the
// operand order the Go compiler happens to pick for the scalar body. For
// those ops a lane where BOTH sides produced some NaN counts as equal;
// everything else (comparisons, selects, all integer ops) must match
// bit-for-bit.
""" + why + """
func nanLanes(name string) int {
	switch name {
	case """ + cases32 + """:
		return 4
	case """ + cases64 + """:
		return 2
	}
	return 0
}

func laneIsNaN(v [2]uint64, lanes, i int) bool {
	if lanes == 4 {
		x := uint32(v[i>>1] >> (32 * uint(i&1)))
		return x&0x7f800000 == 0x7f800000 && x&0x007fffff != 0
	}
	x := v[i]
	return x&0x7ff0000000000000 == 0x7ff0000000000000 && x&0x000fffffffffffff != 0
}

func simdEq(got, want [2]uint64, lanes int) bool {
	if got == want {
		return true
	}
	if lanes == 0 {
		return false
	}
	for i := 0; i < lanes; i++ {
		var g, w uint64
		if lanes == 4 {
			g = uint64(uint32(got[i>>1] >> (32 * uint(i&1))))
			w = uint64(uint32(want[i>>1] >> (32 * uint(i&1))))
		} else {
			g, w = got[i], want[i]
		}
		if g == w {
			continue
		}
		if !laneIsNaN(got, lanes, i) || !laneIsNaN(want, lanes, i) {
			return false
		}
	}
	return true
}

func TestSimdAsmMatchesScalar(t *testing.T) {
	for name, fns := range simdAsm_vv_v {
		lanes := nanLanes(name)
		for _, a := range simdAsmCorpus {
			for _, b := range simdAsmCorpus {
				if got, want := fns[0](a, b), fns[1](a, b); !simdEq(got, want, lanes) {
					t.Fatalf("%s(%x, %x) = %x, scalar %x", name, a, b, got, want)
				}
			}
		}
	}
	for name, fns := range simdAsm_v_v {
		for _, a := range simdAsmCorpus {
			if got, want := fns[0](a), fns[1](a); got != want {
				t.Fatalf("%s(%x) = %x, scalar %x", name, a, got, want)
			}
		}
	}
	for name, fns := range simdAsm_vvv_v {
		for _, a := range simdAsmCorpus {
			for _, b := range simdAsmCorpus {
				c := [2]uint64{a[1] ^ b[0], a[0]}
				if got, want := fns[0](a, b, c), fns[1](a, b, c); got != want {
					t.Fatalf("%s(%x, %x, %x) = %x, scalar %x", name, a, b, c, got, want)
				}
			}
		}
	}
	for name, fns := range simdAsm_vs_v {
		for _, a := range simdAsmCorpus {
			for _, s := range simdAsmShifts {
				if got, want := fns[0](a, s), fns[1](a, s); got != want {
					t.Fatalf("%s(%x, %d) = %x, scalar %x", name, a, s, got, want)
				}
			}
		}
	}
	for name, fns := range simdAsm_v_i32 {
		for _, a := range simdAsmCorpus {
			if got, want := fns[0](a), fns[1](a); got != want {
				t.Fatalf("%s(%x) = %d, scalar %d", name, a, got, want)
			}
		}
	}
	for name, fns := range simdAsm_v_i64 {
		for _, a := range simdAsmCorpus {
			if got, want := fns[0](a), fns[1](a); got != want {
				t.Fatalf("%s(%x) = %#x, scalar %#x", name, a, got, want)
			}
		}
	}
	for name, fns := range simdAsm_s32_v {
		for _, s := range []int32{0, 1, -1, 127, -128, 255, 32767, -32768, 1 << 30, -(1 << 30)} {
			if got, want := fns[0](s), fns[1](s); got != want {
				t.Fatalf("%s(%d) = %x, scalar %x", name, s, got, want)
			}
		}
	}
	for name, fns := range simdAsm_s64_v {
		for _, s := range []int64{0, 1, -1, 1 << 62, -(1 << 62)} {
			if got, want := fns[0](s), fns[1](s); got != want {
				t.Fatalf("%s(%d) = %x, scalar %x", name, s, got, want)
			}
		}
	}
	for name, fns := range simdAsm_f32_v {
		for _, a := range simdAsmCorpus {
			s := math.Float32frombits(uint32(a[0]))
			if got, want := fns[0](s), fns[1](s); got != want {
				t.Fatalf("%s(%v) = %x, scalar %x", name, s, got, want)
			}
		}
	}
	for name, fns := range simdAsm_f64_v {
		for _, a := range simdAsmCorpus {
			s := math.Float64frombits(a[0])
			if got, want := fns[0](s), fns[1](s); got != want {
				t.Fatalf("%s(%v) = %x, scalar %x", name, s, got, want)
			}
		}
	}
}
""")
    open(path, "w").write("\n".join(t))

GCASM = "internal/gcasm"

# ---------------------------------------------------------------------------
# Memory-op splice sequences (gcasm only — the helpers for these are Go
# functions with an inline bounds check, not asm). Each entry: helper op
# name → (guest access size in bytes, lines executed with the guest
# address in x27). Loads leave the result in v0; the store expects the
# value in v0. The gcasm splice emits the effective-address computation
# and bounds check around these (see simdsplice_a64.go).
# ---------------------------------------------------------------------------

A64_MEM = {
    "v128_load":        (16, ["ldr q0, [x27]"]),
    "v128_store":       (16, ["str q0, [x27]"]),
    "v128_load8x8_s":   (8,  ["ldr d0, [x27]", "sxtl v0.8h, v0.8b"]),
    "v128_load8x8_u":   (8,  ["ldr d0, [x27]", "uxtl v0.8h, v0.8b"]),
    "v128_load16x4_s":  (8,  ["ldr d0, [x27]", "sxtl v0.4s, v0.4h"]),
    "v128_load16x4_u":  (8,  ["ldr d0, [x27]", "uxtl v0.4s, v0.4h"]),
    "v128_load32x2_s":  (8,  ["ldr d0, [x27]", "sxtl v0.2d, v0.2s"]),
    "v128_load32x2_u":  (8,  ["ldr d0, [x27]", "uxtl v0.2d, v0.2s"]),
    "v128_load8_splat": (1,  ["ld1r {v0.16b}, [x27]"]),
    "v128_load16_splat": (2, ["ld1r {v0.8h}, [x27]"]),
    "v128_load32_splat": (4, ["ld1r {v0.4s}, [x27]"]),
    "v128_load64_splat": (8, ["ld1r {v0.2d}, [x27]"]),
    "v128_load32_zero": (4,  ["ldr s0, [x27]"]),
    "v128_load64_zero": (8,  ["ldr d0, [x27]"]),
}

def emit_splice_tables(sigs, arm_covered, amd_covered, enc):
    """Emit the gcasm splice tables: the same op bodies as the helper .s
    files, as Go string tables the transform inlines at a call site
    instead of marshalling an ABI0 call. Conventions are the helpers'
    (v128 args in F0..F2 / X0..X2 in declaration order, int scalar in
    R0 / AX, float scalar in F0 / X0; v128 result in F0 / X0, scalar
    result in R0 / AX) — the tables ARE the helper bodies, minus the FP
    loads/stores around them.

    `·simdConst*` references stay in the lines; the splice rewrites them
    onto interned ConstPool blobs, because the transformed package
    cannot name another package's data symbols from Plan9 asm. The
    constant contents are emitted alongside, keyed by name."""
    b16 = []
    for v in [1, 2, 4, 8, 16, 32, 64, 128]:
        b16 += [v & 0xFF, v >> 8]
    a64_consts = {
        "simdConstBitpos8": bytes([1, 2, 4, 8, 16, 32, 64, 128] * 2),
        "simdConstBitpos16": bytes(b16),
        "simdConstBitpos32": b"".join(v.to_bytes(4, "little") for v in (1, 2, 4, 8)),
    }
    def quote(l):
        return '"%s"' % l.replace("\\", "\\\\").replace('"', '\\"')
    out = [
        "// Code generated by tools/gen-simd-asm/gen.py; DO NOT EDIT.",
        "",
        "package gcasm",
        "",
        "// a64SimdSpliceTab: op → arm64 body lines (WORD-encoded NEON plus",
        "// the occasional native line). See simdsplice_a64.go for how a",
        "// call site is rewritten around these.",
        "var a64SimdSpliceTab = map[string][]string{",
    ]
    for name in sorted(arm_covered):
        op = name.removeprefix("simd_")
        lines = []
        for line in A64[op]:
            if line.startswith("go:"):
                lines.append(line[3:])
            else:
                lines.append(f"WORD $0x{enc[line]:08x} // {line}")
        out.append(f'\t"{op}": {{{", ".join(quote(l) for l in lines)}}},')
    out.append("}")
    out.append("")
    out.append("// x64SimdSpliceTab: op → amd64 body lines (native Go asm, SSE,")
    out.append("// x86-64-v2 baseline — the same guard as the helper bodies).")
    out.append("var x64SimdSpliceTab = map[string][]string{")
    for name in sorted(amd_covered):
        op = name.removeprefix("simd_")
        out.append(f'\t"{op}": {{{", ".join(quote(l) for l in X64[op])}}},')
    out.append("}")
    out.append("")
    out.append("// simdSpliceConsts: the 16-byte tables the bodies reference,")
    out.append("// interned into the ConstPool at splice time.")
    out.append("var simdSpliceConsts = map[string][]byte{")
    for cname, byts in sorted({**a64_consts, **X64_CONSTS}.items()):
        out.append(f'\t"{cname}": {{{", ".join("0x%02x" % b for b in byts)}}},')
    out.append("}")
    out.append("")
    mem_enc = encode_gas({k: lines for k, (_, lines) in A64_MEM.items()})
    out.append("// a64SimdMemSpliceTab: memory op → guest access size and the")
    out.append("// body lines run with the checked guest address in R27 (x27).")
    out.append("var a64SimdMemSpliceTab = map[string]struct {")
    out.append("\tSize  int")
    out.append("\tLines []string")
    out.append("}{")
    for op in sorted(A64_MEM):
        size, lines = A64_MEM[op]
        rendered = ", ".join(quote(f"WORD $0x{mem_enc[l]:08x} // {l}") for l in lines)
        out.append(f'\t"{op}": {{Size: {size}, Lines: []string{{{rendered}}}}},')
    out.append("}")
    out.append("")
    open(f"{GCASM}/simdsplicetab_gen.go", "w").write("\n".join(out))

def emit_pair_wrappers(sigs):
    """simd_pair.go: the scalar-pair forms `simd_p_<op>` of every pure
    op. The scalarized emitter calls these so v128 values live as two
    uint64 locals -- which Go's register allocator keeps in registers,
    where [2]uint64 arrays are always stack-assigned. Each wrapper just
    packs/unpacks around the array-form op; the gcasm backend splices
    the calls away entirely, and everywhere else they are small enough
    to inline. The simd_ prefix keeps them inside appendSimdHelperFiles'
    multi-package rename (simd_ -> Simd_)."""
    out = [
        "// Code generated by tools/gen-simd-asm/gen.py; DO NOT EDIT.",
        "",
        "package helpers",
        "",
    ]
    for name in sorted(sigs):
        params, ret = sigs[name]
        kinds = param_kinds(params)
        sig_parts, call_parts = [], []
        for pname, typ in kinds:
            if typ == "[2]uint64":
                sig_parts.append(f"{pname}0, {pname}1 uint64")
                call_parts.append(f"[2]uint64{{{pname}0, {pname}1}}")
            else:
                sig_parts.append(f"{pname} {typ}")
                call_parts.append(pname)
        pname_sig = ", ".join(sig_parts)
        call = f"{name}({', '.join(call_parts)})"
        wname = name.replace("simd_", "simd_p_", 1)
        # noinline: the gcasm splice matches the CALL; inlined, gc would
        # resurrect the array form inside the caller.
        out.append("//go:noinline")
        if ret == "[2]uint64":
            out.append(f"func {wname}({pname_sig}) (uint64, uint64) {{")
            out.append(f"\tr := {call}")
            out.append("\treturn r[0], r[1]")
            out.append("}")
        else:
            out.append(f"func {wname}({pname_sig}) {ret} {{ return {call} }}")
        out.append("")
    open(f"{HELPERS}/simd_pair.go", "w").write("\n".join(out))


# ---------------------------------------------------------------------------
# Pair-form splice sequences (gcasm). The scalarized emitter calls
# simd_p_<op>(halves...) with everything in REGISTERS (uint64 pairs and
# scalars in x0.., floats in s0/d0), results as (x0, x1) or a scalar.
# These tables give the complete inline body per op: build V registers
# from the GPR pairs, run the op, move the result back. Lane and memory
# ops get dedicated GPR-only sequences (no immediate-lane restriction,
# no stack).
# ---------------------------------------------------------------------------

def pair_pure_sequences(sigs, arm_covered):
    """op → full GAS/go: line list for the pair-form call."""
    out = {}
    for name in sorted(arm_covered):
        op = name.removeprefix("simd_")
        if "extract_lane" in op or "replace_lane" in op:
            continue  # dedicated GPR sequences below
        params, ret = sigs[name]
        kinds = param_kinds(params)
        gpr = 0
        vord = 0
        lines = []
        moves = []
        bad = False
        for pname, typ in kinds:
            if typ == "[2]uint64":
                lines.append(f"fmov d{vord}, x{gpr}")
                lines.append(f"mov v{vord}.d[1], x{gpr+1}")
                gpr += 2
                vord += 1
            elif typ in ("int32", "uint32", "int64"):
                # Bodies expect the (single) int scalar in w0/x0.
                if gpr != 0:
                    moves.append(f"mov x0, x{gpr}")
                gpr += 1
            elif typ in ("float32", "float64"):
                # Float scalars only occur on the splats (no v128
                # params), already in s0/d0.
                if vord != 0:
                    bad = True
            else:
                bad = True
        if bad:
            continue
        lines.extend(moves)
        for l in A64[op]:
            lines.append(l)  # go: lines pass through
        if ret == "[2]uint64":
            lines.append("fmov x0, d0")
            lines.append("mov x1, v0.d[1]")
        out[op] = lines
    return out

def pair_lane_sequences():
    """extract/replace lane, GPR-only: (a0,a1[,lane[,val]]) in x0,x1,w2,(x3|s0|d0)."""
    out = {}
    shapes = [("i8x16", 0, 8), ("i16x8", 1, 16), ("i32x4", 2, 32),
              ("i64x2", 3, 64), ("f32x4", 2, 32), ("f64x2", 3, 64)]
    for shape, s, w in shapes:
        base = [f"lsl w27, w2, #{3+s}",
                "cmp w27, #64",
                "csel x25, x1, x0, hs",
                "and x27, x27, #63",
                "lsr x25, x25, x27"]
        if shape == "i8x16":
            out["i8x16_extract_lane_s"] = base + ["sxtb w0, w25"]
            out["i8x16_extract_lane_u"] = base + ["and w0, w25, #255"]
        elif shape == "i16x8":
            out["i16x8_extract_lane_s"] = base + ["sxth w0, w25"]
            out["i16x8_extract_lane_u"] = base + ["and w0, w25, #65535"]
        elif shape == "i32x4":
            out["i32x4_extract_lane"] = base + ["mov w0, w25"]
        elif shape == "i64x2":
            out["i64x2_extract_lane"] = ["cmp w2, #1", "csel x0, x1, x0, eq"]
        elif shape == "f32x4":
            out["f32x4_extract_lane"] = base + ["fmov s0, w25"]
        elif shape == "f64x2":
            out["f64x2_extract_lane"] = ["cmp w2, #1", "csel x25, x1, x0, eq", "fmov d0, x25"]
    def merge(lo_in, hi_in, lane, val, s, w):
        if w == 64:
            return [f"cmp {lane}, #0", f"csel x0, {val}, {lo_in}, eq",
                    f"cmp {lane}, #1", f"csel x1, {val}, {hi_in}, eq"]
        mask = (1 << w) - 1
        return [f"lsl w27, {lane}, #{3+s}",
                "and x26, x27, #63",
                f"mov x25, #{mask}",
                "lsl x25, x25, x26",
                f"lsl x24, {val}, x26",
                "and x24, x24, x25",
                f"bic x23, {lo_in}, x25",
                "orr x23, x23, x24",
                f"bic x22, {hi_in}, x25",
                "orr x22, x22, x24",
                "cmp w27, #64",
                f"csel x0, x23, {lo_in}, lo",
                f"csel x1, {hi_in}, x22, lo"]
    for shape, s, w in shapes:
        pre = []
        val = "x3"
        if shape == "f32x4":
            pre = ["fmov w3, s0"]
        elif shape == "f64x2":
            pre = ["fmov x3, d0"]
        out[f"{shape}_replace_lane"] = pre + merge("x0", "x1", "w2", val, s, w)
    return out, merge

def pair_mem_sequences(merge):
    """memory ops in pair form. The Go-side preamble leaves the checked
    guest address in x27 and preserves x3..x5 (value/lane args)."""
    out = {}
    ext = {"8x8_s": ("sxtl v0.8h, v0.8b"), "8x8_u": ("uxtl v0.8h, v0.8b"),
           "16x4_s": ("sxtl v0.4s, v0.4h"), "16x4_u": ("uxtl v0.4s, v0.4h"),
           "32x2_s": ("sxtl v0.2d, v0.2s"), "32x2_u": ("uxtl v0.2d, v0.2s")}
    pairout = ["fmov x0, d0", "mov x1, v0.d[1]"]
    out["v128_load"] = (16, ["ldp x0, x1, [x27]"])
    out["v128_store"] = (16, ["stp x3, x4, [x27]"])
    # Packed f16 store conversion: four f32 lanes -> f16 with the
    # software idiom's semantics (NaN forced to sign|0x7E00), stored
    # as one 8-byte word. Mirrors the fused-region store case.
    out["v128_f16x4_cvt_store"] = (8, [
        "fmov d0, x3", "mov v0.d[1], x4",
        "fcvtn v1.4h, v0.4s",
        "fcmeq v2.4s, v0.4s, v0.4s",
        "ushr v3.4s, v0.4s, #16",
        "movi v4.4s, #0x80, lsl #8",
        "and v3.16b, v3.16b, v4.16b",
        "movi v4.4s, #0x7e, lsl #8",
        "orr v3.16b, v3.16b, v4.16b",
        "xtn v2.4h, v2.4s",
        "xtn v3.4h, v3.4s",
        "bsl v2.8b, v1.8b, v3.8b",
        "str d2, [x27]",
    ])
    for k, sx in ext.items():
        out[f"v128_load{k}"] = (8, ["ldr d0, [x27]", sx] + pairout)
    for k, arr in [("8", "16b"), ("16", "8h"), ("32", "4s"), ("64", "2d")]:
        out[f"v128_load{k}_splat"] = (int(k) // 8, [f"ld1r {{v0.{arr}}}, [x27]"] + pairout)
    out["v128_load32_zero"] = (4, ["ldr w0, [x27]", "mov x1, #0"])
    out["v128_load64_zero"] = (8, ["ldr x0, [x27]", "mov x1, #0"])
    lane_ld = {"8": ("ldrb w24, [x27]", 0, 8), "16": ("ldrh w24, [x27]", 1, 16),
               "32": ("ldr w24, [x27]", 2, 32), "64": ("ldr x24, [x27]", 3, 64)}
    for k, (ld, s, w) in lane_ld.items():
        out[f"v128_load{k}_lane"] = (w // 8, [ld] + merge("x4", "x5", "w3", "x24", s, w))
    lane_st = {"8": ("strb w24, [x27]", 0, 8), "16": ("strh w24, [x27]", 1, 16),
               "32": ("str w24, [x27]", 2, 32), "64": ("str x24, [x27]", 3, 64)}
    for k, (stl, s, w) in lane_st.items():
        # Extract runs BEFORE the preamble (it clobbers x27), so it is
        # emitted as the PRE part; the table only holds the store.
        pre = [f"lsl w27, w3, #{3+s}",
               "cmp w27, #64",
               "csel x25, x5, x4, hs",
               "and x27, x27, #63",
               "lsr x24, x25, x27"] if w != 64 else               ["cmp w3, #1", "csel x24, x5, x4, eq"]
        out[f"v128_store{k}_lane"] = (w // 8, [stl])
        out[f"v128_store{k}_lane_pre"] = (w // 8, pre)
    return out

def emit_pair_splice_tables(sigs, arm_covered, amd_covered):
    pure = pair_pure_sequences(sigs, arm_covered)
    lanes, merge = pair_lane_sequences()
    mems = pair_mem_sequences(merge)
    every = {}
    for op, lines in {**pure, **lanes}.items():
        every[op] = lines
    for op, (_, lines) in mems.items():
        every["mem:" + op] = lines
    enc = encode_gas(every)
    def render(lines):
        r = []
        for l in lines:
            if l.startswith("go:"):
                r.append(l[3:])
            else:
                r.append(f"WORD $0x{enc[l]:08x} // {l}")
        return ", ".join('"%s"' % x.replace("\\", "\\\\").replace('"', '\\"') for x in r)
    out = [
        "// Code generated by tools/gen-simd-asm/gen.py; DO NOT EDIT.",
        "",
        "package gcasm",
        "",
        "// a64SimdPairSpliceTab: pair-form op (simd_p_<op>) → complete",
        "// inline body. Args ride the register ABI: uint64 halves and int",
        "// scalars in x0.., float scalars in s0/d0; results in (x0, x1)",
        "// or the scalar register.",
        "var a64SimdPairSpliceTab = map[string][]string{",
    ]
    for op in sorted(set(list(pure) + list(lanes))):
        out.append(f'\t"{op}": {{{render((pure | lanes)[op])}}},')
    out.append("}")
    out.append("")
    out.append("// a64SimdPairMemSpliceTab: pair-form memory ops. Size is the")
    out.append("// guest access width for the bounds check; Pre runs before the")
    out.append("// address preamble (extracting the stored element while x27 is")
    out.append("// still free); Lines run with the checked address in x27.")
    out.append("var a64SimdPairMemSpliceTab = map[string]struct {")
    out.append("\tSize  int")
    out.append("\tPre   []string")
    out.append("\tLines []string")
    out.append("}{")
    for op in sorted(k for k in mems if not k.endswith("_pre")):
        size, lines = mems[op]
        pre = mems.get(op + "_pre", (0, []))[1]
        pre_r = render(pre) if pre else ""
        out.append(f'\t"{op}": {{Size: {size}, Pre: []string{{{pre_r}}}, Lines: []string{{{render(lines)}}}}},')
    out.append("}")
    out.append("")
    open(f"{GCASM}/simdsplicepairtab_gen.go", "w").write("\n".join(out))

    # The emitter must only emit pair-form calls the gcasm splice can
    # take over completely: a pair call that survived to a real CALL
    # could not be marshalled (two results). This table is that
    # contract, generated from the same source as the splice tables.
    co = [
        "// Code generated by tools/gen-simd-asm/gen.py; DO NOT EDIT.",
        "",
        "package codegen",
        "",
        "// simdPairOps lists the ops whose scalar-pair form the gcasm",
        "// backend splices inline. The scalarizer emits simd_p_<op> only",
        "// for these; every other op keeps its array form (bridged at",
        "// the boundary), because a surviving two-result call could not",
        "// be marshalled.",
        "var simdPairOps = map[string]bool{",
    ]
    x64pure = x64_pair_pure_sequences(sigs, amd_covered)
    both = (set(pure) & set(x64pure)) | set(lanes) | {k for k in mems if not k.endswith("_pre")}
    # The bounds-coalescing pass's split forms: the group-leading
    # range-checked load and the unchecked members, spliced by
    # dedicated code (not tables).
    both |= {"v128_load_nc", "v128_load_rng"}
    for op in sorted(both):
        co.append(f'\t"{op}": true,')
    co.append("}")
    co.append("")
    co.append("// simdFusePureOps are the pure pair ops whose BOTH-arch splice")
    co.append("// bodies stay inside the vector file after their operand-build")
    co.append("// prefix, scalar staging, and result moves are stripped — i.e.")
    co.append("// safe members for a fused region, where GPRs beyond the")
    co.append("// staging register hold live fused arguments. Computed by the")
    co.append("// same classification the fused splicers apply at build time.")
    co.append("var simdFusePureOps = map[string]bool{")
    for op in sorted(set(pure) & set(x64pure)):
        params, ret = sigs["simd_" + op]
        if ret != "[2]uint64":
            continue
        kinds = param_kinds(params)
        if any(t in ("float32", "float64", "int64") for _, t in kinds):
            continue
        if not fuse_core_clean_a64(pure[op]) or not fuse_core_clean_x64(x64pure[op]):
            continue
        co.append(f'\t"{op}": true,')
    co.append("}")
    co.append("")
    open("internal/codegen/simd_pairable_gen.go", "w").write("\n".join(co))


def fuse_core_clean_a64(lines):
    """True when the body's core touches no GPR beyond x0/w0."""
    i = 0
    while i < len(lines) and re.match(r"fmov d\d+, x\d+$", lines[i]):
        i += 2  # build-lo + build-hi
    if i < len(lines) and re.match(r"mov x0, x\d+$", lines[i]):
        i += 1
    for l in lines[i:]:
        if l.startswith("go:"):
            return False
        if l in ("fmov x0, d0", "mov x1, v0.d[1]"):
            continue
        for m in re.finditer(r"\b[xw](\d+)\b", l):
            if m.group(1) != "0":
                return False
    return True


def fuse_core_clean_x64(lines):
    """True when the body's core touches no GPR beyond AX."""
    i = 0
    while i < len(lines) and re.match(r"MOVQ [A-Z0-9]+, X\d+$", lines[i]) and i + 1 < len(lines) and lines[i+1].startswith("PINSRQ $1, "):
        i += 2
    if i < len(lines) and re.match(r"MOVQ [A-Z][A-Z0-9]*, AX$", lines[i]):
        i += 1
    for l in lines[i:]:
        if l in ("PEXTRQ $1, X0, BX", "MOVQ X0, AX"):
            continue
        for m in re.finditer(r"\b(AX|BX|CX|DX|DI|SI|BP|R\d+)\b", l):
            if m.group(1) != "AX":
                return False
    return True


# ---------------------------------------------------------------------------
# amd64 pair-form splice sequences. Same contract as the arm64 pair
# tables: args ride the register ABI (int order AX, BX, CX, DI, SI, R8,
# R9; float scalars in X0), results in (AX, BX) or the scalar register.
# All lines are native Go asm (the Go assembler's SSE coverage is
# complete), so no encoder pass is needed. x86-64-v2 baseline, same as
# the helper bodies (PINSRQ/PEXTRQ/PMOVSX are SSE4.1).
# ---------------------------------------------------------------------------

X64_INT_ORDER = ["AX", "BX", "CX", "DI", "SI", "R8", "R9", "R10", "R11"]

def x64_pair_pure_sequences(sigs, amd_covered):
    out = {}
    for name in sorted(amd_covered):
        op = name.removeprefix("simd_")
        if "extract_lane" in op or "replace_lane" in op:
            continue
        params, ret = sigs[name]
        kinds = param_kinds(params)
        gi = 0
        vord = 0
        lines = []
        moves = []
        bad = False
        for pname, typ in kinds:
            if typ == "[2]uint64":
                lo, hi = X64_INT_ORDER[gi], X64_INT_ORDER[gi+1]
                lines.append(f"MOVQ {lo}, X{vord}")
                lines.append(f"PINSRQ $1, {hi}, X{vord}")
                gi += 2
                vord += 1
            elif typ in ("int32", "uint32", "int64"):
                if gi != 0:
                    moves.append(f"MOVQ {X64_INT_ORDER[gi]}, AX")
                gi += 1
            elif typ in ("float32", "float64"):
                if vord != 0:
                    bad = True
            else:
                bad = True
        if bad:
            continue
        lines.extend(moves)
        lines.extend(X64[op])
        if ret == "[2]uint64":
            # PEXTRQ before MOVQ: MOVQ X0, AX would be fine either way,
            # but extracting the high half first keeps X0 unread after
            # the low move for the transfer-forwarding pass someday.
            lines.append("PEXTRQ $1, X0, BX")
            lines.append("MOVQ X0, AX")
        out[op] = lines
    return out

def x64_lane_extract(lo, hi, lane, s, w, variant):
    """GPR-only lane extract: value halves in lo/hi, lane count in
    `lane` (must be CX: x86 variable shifts take CL)."""
    assert lane == "CX"
    if w == 64:
        seq = [f"MOVQ {lo}, R10", f"TESTL $1, {lane}", f"CMOVQNE {hi}, R10"]
    else:
        seq = [f"SHLL ${3+s}, {lane}",
               f"MOVQ {lo}, R10",
               f"TESTL $64, {lane}",
               f"CMOVQNE {hi}, R10",
               f"ANDL $63, {lane}",
               f"SHRQ CX, R10"]
    ext = {
        "i8_s": ["MOVBQSX R10, AX"], "i8_u": ["MOVBQZX R10, AX"],
        "i16_s": ["MOVWQSX R10, AX"], "i16_u": ["MOVWQZX R10, AX"],
        "i32": ["MOVL R10, AX"], "i64": ["MOVQ R10, AX"],
        "f32": ["MOVL R10, X0"], "f64": ["MOVQ R10, X0"],
    }[variant]
    return seq + ext

def x64_lane_merge(lo, hi, lane, val, s, w):
    """GPR-only lane replace: merge `val` into the (lo,hi) pair at
    `lane`, result in (AX, BX). lane must be CX (CL shifts)."""
    assert lane == "CX"
    if w == 64:
        return [f"MOVQ {lo}, AX", f"MOVQ {hi}, BX",
                f"TESTL $1, {lane}",
                f"CMOVQEQ {val}, AX",
                f"CMOVQNE {val}, BX"]
    mask = (1 << w) - 1
    return [f"SHLL ${3+s}, {lane}",
            "MOVL CX, R13",          # full bit offset, for the half test
            f"ANDL $63, {lane}",
            f"MOVQ ${mask}, R10",
            "SHLQ CX, R10",           # mask << rem
            f"MOVQ {val}, R11",
            "SHLQ CX, R11",
            "ANDQ R10, R11",          # val placed
            "NOTQ R10",
            f"MOVQ {lo}, AX",
            f"MOVQ {hi}, BX",
            "MOVQ AX, R12",
            "ANDQ R10, R12",
            "ORQ R11, R12",           # merged low
            "MOVQ BX, DX",
            "ANDQ R10, DX",
            "ORQ R11, DX",            # merged high
            "TESTL $64, R13",
            "CMOVQEQ R12, AX",
            "CMOVQNE DX, BX"]

def x64_pair_lane_sequences():
    out = {}
    shapes = [("i8x16", 0, 8), ("i16x8", 1, 16), ("i32x4", 2, 32),
              ("i64x2", 3, 64), ("f32x4", 2, 32), ("f64x2", 3, 64)]
    for shape, s, w in shapes:
        if shape == "i8x16":
            out["i8x16_extract_lane_s"] = x64_lane_extract("AX", "BX", "CX", s, w, "i8_s")
            out["i8x16_extract_lane_u"] = x64_lane_extract("AX", "BX", "CX", s, w, "i8_u")
        elif shape == "i16x8":
            out["i16x8_extract_lane_s"] = x64_lane_extract("AX", "BX", "CX", s, w, "i16_s")
            out["i16x8_extract_lane_u"] = x64_lane_extract("AX", "BX", "CX", s, w, "i16_u")
        else:
            variant = {"i32x4": "i32", "i64x2": "i64", "f32x4": "f32", "f64x2": "f64"}[shape]
            out[f"{shape}_extract_lane"] = x64_lane_extract("AX", "BX", "CX", s, w, variant)
    for shape, s, w in shapes:
        pre = []
        val = "DI"
        if shape == "f32x4":
            pre = ["MOVL X0, DI"]
        elif shape == "f64x2":
            pre = ["MOVQ X0, DI"]
        out[f"{shape}_replace_lane"] = pre + x64_lane_merge("AX", "BX", "CX", val, s, w)
    return out

def x64_pair_mem_sequences():
    """Pair-form memory ops, amd64. The Go-side preamble leaves the
    checked host address in R11 and preserves DI/SI/R8 (lane and value
    args). Value pair for plain stores arrives in (DI, SI); lane ops
    are (m,addr,off,lane,v0,v1) = AX,BX,CX,DI,SI,R8."""
    pairout = ["PEXTRQ $1, X0, BX", "MOVQ X0, AX"]
    out = {}
    out["v128_load"] = (16, [], ["MOVQ (R11), AX", "MOVQ 8(R11), BX"])
    out["v128_store"] = (16, [], ["MOVQ DI, (R11)", "MOVQ SI, 8(R11)"])
    def _c4(w):
        # Materialize a 4-lane u32 constant in X4 without symbol
        # references (the spliced table lines cannot name package data).
        q = w | (w << 32)
        return [f"MOVQ ${-((~q)&0xFFFFFFFFFFFFFFFF)-1 if q >= 1<<63 else q}, AX",
                "MOVQ AX, X4", "PSHUFD $0x44, X4, X4"]
    cvt = ["MOVQ DI, X0", "PINSRQ $1, SI, X0", "MOVOU X0, X1"]
    cvt += _c4(0x7FFFFFFF) + ["PAND X4, X1"]
    cvt += _c4(0x80000000) + ["PXOR X4, X1"]
    cvt += _c4(0xFF800000) + ["PCMPGTL X4, X1"]
    cvt += ["MOVOU X0, X2", "PSRLL $16, X2"] + _c4(0x8000) + ["PAND X4, X2"]
    cvt += ["MOVOU X1, X3"] + _c4(0x7E00) + ["PAND X4, X3", "POR X3, X2"]
    cvt += ["MOVOU X0, X3", "PSLLL $1, X3"] + _c4(0xFF000000) + ["PAND X4, X3"]
    cvt += _c4(0x71000000) + ["PMAXUD X4, X3", "PSRLL $1, X3"]
    cvt += _c4(0x07800000) + ["PADDL X4, X3"]
    cvt += _c4(0x7FFFFFFF) + ["PAND X4, X0"]
    cvt += _c4(0x77800000) + ["MULPS X4, X0"]
    cvt += _c4(0x08800000) + ["MULPS X4, X0", "ADDPS X3, X0"]
    cvt += ["MOVOU X0, X3", "PSRLL $13, X3"] + _c4(0x7C00) + ["PAND X4, X3"]
    cvt += _c4(0xFFF) + ["PAND X4, X0", "PADDL X0, X3"]
    cvt += ["PANDN X3, X1", "POR X1, X2", "PACKUSDW X2, X2", "MOVQ X2, (R11)"]
    out["v128_f16x4_cvt_store"] = (8, [], cvt)
    ext = {"8x8_s": "PMOVSXBW", "8x8_u": "PMOVZXBW", "16x4_s": "PMOVSXWD",
           "16x4_u": "PMOVZXWD", "32x2_s": "PMOVSXDQ", "32x2_u": "PMOVZXDQ"}
    for k, insn in ext.items():
        out[f"v128_load{k}"] = (8, [], ["MOVQ (R11), X0", f"{insn} X0, X0"] + pairout)
    splat_load = {"8": ("MOVBLZX (R11), AX", "i8x16_splat"),
                  "16": ("MOVWLZX (R11), AX", "i16x8_splat"),
                  "32": ("MOVL (R11), AX", "i32x4_splat"),
                  "64": ("MOVQ (R11), AX", "i64x2_splat")}
    for k, (ld, splat) in splat_load.items():
        out[f"v128_load{k}_splat"] = (int(k) // 8, [], [ld] + X64[splat] + pairout)
    out["v128_load32_zero"] = (4, [], ["MOVL (R11), AX", "XORQ BX, BX"])
    out["v128_load64_zero"] = (8, [], ["MOVQ (R11), AX", "XORQ BX, BX"])
    # The loaded element rides R9: the merge sequence uses R10-R13 as
    # its own scratch.
    lane_ld = {"8": ("MOVBLZX (R11), R9", 0, 8), "16": ("MOVWLZX (R11), R9", 1, 16),
               "32": ("MOVL (R11), R9", 2, 32), "64": ("MOVQ (R11), R9", 3, 64)}
    for k, (ld, s, w) in lane_ld.items():
        # lane in DI must reach CX for the CL shifts; CX (offset) is
        # consumed by the preamble already.
        merge = ["MOVQ DI, CX"] + x64_lane_merge("SI", "R8", "CX", "R9", s, w)
        out[f"v128_load{k}_lane"] = (w // 8, [], [ld] + merge)
    # The element extract runs AFTER the preamble: it needs CX for the
    # CL-count shift, and CX still holds the offset until the preamble
    # has consumed it. R11 (the checked address) is preserved.
    lane_st = {"8": ("MOVB R10, (R11)", 0, 8), "16": ("MOVW R10, (R11)", 1, 16),
               "32": ("MOVL R10, (R11)", 2, 32), "64": ("MOVQ R10, (R11)", 3, 64)}
    for k, (stl, s, w) in lane_st.items():
        if w == 64:
            ext = ["MOVQ SI, R10", "TESTL $1, DI", "CMOVQNE R8, R10"]
        else:
            ext = ["MOVQ DI, CX",
                   f"SHLL ${3+s}, CX",
                   "MOVQ SI, R10",
                   "TESTL $64, CX",
                   "CMOVQNE R8, R10",
                   "ANDL $63, CX",
                   "SHRQ CX, R10"]
        out[f"v128_store{k}_lane"] = (w // 8, [], ext + [stl])
    return out

def emit_x64_pair_splice_tables(sigs, amd_covered):
    pure = x64_pair_pure_sequences(sigs, amd_covered)
    lanes = x64_pair_lane_sequences()
    mems = x64_pair_mem_sequences()
    def quote(l):
        return '"%s"' % l.replace("\\", "\\\\").replace('"', '\\"')
    def render(lines):
        return ", ".join(quote(l) for l in lines)
    out = [
        "// Code generated by tools/gen-simd-asm/gen.py; DO NOT EDIT.",
        "",
        "package gcasm",
        "",
        "// x64SimdPairSpliceTab: pair-form op -> complete amd64 inline",
        "// body (native Go asm, SSE, x86-64-v2). Args ride the register",
        "// ABI (AX, BX, CX, DI, SI, R8, ...; float scalars in X0);",
        "// results in (AX, BX) or the scalar register.",
        "var x64SimdPairSpliceTab = map[string][]string{",
    ]
    for op in sorted(set(list(pure) + list(lanes))):
        out.append(f'\t"{op}": {{{render((pure | lanes)[op])}}},')
    out.append("}")
    out.append("")
    out.append("// x64SimdPairMemSpliceTab: pair-form memory ops, amd64. Pre")
    out.append("// runs before the address preamble; Lines run with the checked")
    out.append("// host address in R11.")
    out.append("var x64SimdPairMemSpliceTab = map[string]struct {")
    out.append("\tSize  int")
    out.append("\tPre   []string")
    out.append("\tLines []string")
    out.append("}{")
    for op in sorted(mems):
        size, pre, lines = mems[op]
        out.append(f'\t"{op}": {{Size: {size}, Pre: []string{{{render(pre)}}}, Lines: []string{{{render(lines)}}}}},')
    out.append("}")
    out.append("")
    open(f"{GCASM}/simdsplicepairtab_amd64_gen.go", "w").write("\n".join(out))

def gen():
    sigs = parse_sigs(f"{HELPERS}/simd_scalar.go")
    arm_covered = {n for n in sigs if n.removeprefix("simd_") in A64}
    amd_covered = {n for n in sigs if n.removeprefix("simd_") in X64}
    for label, table in (("A64", A64), ("X64", X64)):
        extra = sorted(k for k in table if "simd_" + k not in sigs)
        if extra:
            sys.exit(f"{label} entries without scalar twin: {extra}")

    enc = encode_gas({k: v for k, v in A64.items() if "simd_" + k in arm_covered})

    # --- simd_asm_arm64.s ---
    bodies = []
    for name in sorted(arm_covered):
        lines, retoff = arm64_body(name, sigs)
        for line in A64[name.removeprefix("simd_")]:
            if line.startswith("go:"):
                lines.append("\t" + line[3:])
            else:
                lines.append(f"\tWORD $0x{enc[line]:08x} // {line}")
        ret = sigs[name][1]
        if ret == "[2]uint64":
            lines.append(f"\tFMOVQ F0, ret+{retoff}(FP)")
        elif ret == "int32":
            lines.append(f"\tMOVW R0, ret+{retoff}(FP)")
        elif ret == "int64":
            lines.append(f"\tMOVD R0, ret+{retoff}(FP)")
        else:
            sys.exit(f"unhandled ret {ret} for {name}")
        lines.append("\tRET")
        lines.append("")
        bodies.extend(lines)
    b16 = []
    for v in [1, 2, 4, 8, 16, 32, 64, 128]:
        b16 += [v & 0xFF, v >> 8]
    b32 = []
    for v in [1, 2, 4, 8]:
        b32 += list(v.to_bytes(4, "little"))
    emit_asm_file(
        f"{HELPERS}/simd_asm_arm64.s",
        ["// Code generated by tools/gen-simd-asm/gen.py; DO NOT EDIT.",
         "//",
         "// NEON bodies for the simd_* helpers. Vector instructions the Go",
         "// assembler cannot spell are WORD-encoded (fixed registers, so the",
         "// encodings are constants; clang is the encoder ground truth).",
         "",
         '#include "textflag.h"',
         ""],
        [("simdConstBitpos8", bytes([1, 2, 4, 8, 16, 32, 64, 128] * 2)),
         ("simdConstBitpos16", bytes(b16)),
         ("simdConstBitpos32", bytes(b32))],
        bodies)

    # --- simd_asm_amd64.s ---
    bodies = []
    for name in sorted(amd_covered):
        lines, retoff = amd64_body(name, sigs)
        for line in X64[name.removeprefix("simd_")]:
            lines.append("\t" + line)
        ret = sigs[name][1]
        if ret == "[2]uint64":
            lines.append(f"\tMOVOU X0, ret+{retoff}(FP)")
        elif ret == "int32":
            lines.append(f"\tMOVL AX, ret+{retoff}(FP)")
        elif ret == "int64":
            lines.append(f"\tMOVQ AX, ret+{retoff}(FP)")
        else:
            sys.exit(f"unhandled ret {ret} for {name}")
        lines.append("\tRET")
        lines.append("")
        bodies.extend(lines)
    emit_asm_file(
        f"{HELPERS}/simd_asm_amd64.s",
        ["// Code generated by tools/gen-simd-asm/gen.py; DO NOT EDIT.",
         "//",
         "// SSE bodies for the simd_* helpers, x86-64-v2 baseline (the",
         "// amd64.v2 build tag guards them; GOAMD64=v1 builds use the",
         "// scalar fallback aliases instead).",
         "",
         "//go:build amd64.v2",
         "",
         '#include "textflag.h"',
         ""],
        sorted(X64_CONSTS.items()),
        bodies)

    emit_decls(f"{HELPERS}/simd_asm_decls_arm64.go", "arm64", sigs, arm_covered)
    emit_decls(f"{HELPERS}/simd_asm_decls_amd64.go", "amd64.v2", sigs, amd_covered)

    # The full scalar reference set is large Go source. On the asm arches
    # only the uncovered ops need a Go body, so the big file is tagged out
    # there and each arch gets just its own leftovers — the point of the
    # asm backend is to keep generated Go small.
    for tag, covered_set, fname in (
            ("arm64 && !simdmatrix", arm_covered, "simd_scalar_rest_arm64.go"),
            ("amd64.v2 && !simdmatrix", amd_covered, "simd_scalar_rest_amd64.go")):
        emit_scalar_subset(f"{HELPERS}/{fname}", tag, sigs, sorted(set(sigs) - covered_set))

    # --- simd_fallback.go ---
    f = ["// Code generated by tools/gen-simd-asm/gen.py; DO NOT EDIT.",
         "",
         "//go:build !arm64 && !amd64.v2",
         "",
         "package helpers",
         ""]
    for name in sorted(sigs):
        params, ret = sigs[name]
        args = ", ".join(p for p, _ in param_kinds(params))
        f.append(f"func {name}({params}) {ret} {{ return {name}_scalar({args}) }}")
    open(f"{HELPERS}/simd_fallback.go", "w").write("\n".join(f) + "\n")

    emit_pair_matrix_test(f"{HELPERS}/simd_pair_matrix_test.go", sigs, set(sigs))
    emit_matrix_test(f"{HELPERS}/simd_asm_matrix_test.go", "arm64 && simdmatrix", sigs, arm_covered, minmax_tolerant=False)
    emit_matrix_test(f"{HELPERS}/simd_asm_matrix_amd64_test.go", "amd64.v2 && simdmatrix", sigs, amd_covered, minmax_tolerant=True)

    emit_splice_tables(sigs, arm_covered, amd_covered, enc)
    emit_pair_wrappers(sigs)
    emit_pair_splice_tables(sigs, arm_covered, amd_covered)
    emit_x64_pair_splice_tables(sigs, amd_covered)

    covered = arm_covered
    uncovered = sorted(set(sigs) - covered)
    print(f"amd64 covered: {len(amd_covered)}  scalar-only: {len(sigs) - len(amd_covered)}")
    print(f"covered: {len(covered)}  scalar-only: {len(uncovered)}")
    for n in uncovered:
        print("  scalar-only:", n)

if __name__ == "__main__":
    gen()
