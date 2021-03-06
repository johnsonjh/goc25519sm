// Copyright © 2021 Jeffrey H. Johnson <trnsz@pobox.com>.
// Copyright © 2021 Filippo Valsorda.
// Copyright © 2012 The Go Authors.
//
// All rights reserved.
// Use of this source code is governed by the BSD-style
// license that can be found in the LICENSE file.

// This code was translated into a form compatible with
// Go's 6a from the public domain sources in SUPERCOP:
// https://bench.cr.yp.to/supercop.html

// +build amd64,gc,!purego

#include "textflag.h"

#define REDMASK51     0x0007FFFFFFFFFFFF

// These constants cannot be encoded in non-MOVQ immediates.
// We access them directly from memory instead.

DATA ·_121666_213(SB)/8, $996687872
GLOBL ·_121666_213(SB), 8, $8

DATA ·_2P0(SB)/8, $0xFFFFFFFFFFFDA
GLOBL ·_2P0(SB), 8, $8

DATA ·_2P1234(SB)/8, $0xFFFFFFFFFFFFE
GLOBL ·_2P1234(SB), 8, $8

// func freeze(inout *[5]uint64)
TEXT ·freeze(SB), 7, $0-8
	MOVQ inout+0(FP), DI

	MOVQ 0(DI), SI
	MOVQ 8(DI), DX
	MOVQ 16(DI), CX
	MOVQ 24(DI), R8
	MOVQ 32(DI), R9
	MOVQ $REDMASK51, AX
	MOVQ AX, R10
	SUBQ $18, R10
	MOVQ $3, R11

REDUCELOOP:
	MOVQ    SI, R12
	SHRQ    $51, R12
	ANDQ    AX, SI
	ADDQ    R12, DX
	MOVQ    DX, R12
	SHRQ    $51, R12
	ANDQ    AX, DX
	ADDQ    R12, CX
	MOVQ    CX, R12
	SHRQ    $51, R12
	ANDQ    AX, CX
	ADDQ    R12, R8
	MOVQ    R8, R12
	SHRQ    $51, R12
	ANDQ    AX, R8
	ADDQ    R12, R9
	MOVQ    R9, R12
	SHRQ    $51, R12
	ANDQ    AX, R9
	IMUL3Q  $19, R12, R12
	ADDQ    R12, SI
	SUBQ    $1, R11
	JA      REDUCELOOP
	MOVQ    $1, R12
	CMPQ    R10, SI
	CMOVQLT R11, R12
	CMPQ    AX, DX
	CMOVQNE R11, R12
	CMPQ    AX, CX
	CMOVQNE R11, R12
	CMPQ    AX, R8
	CMOVQNE R11, R12
	CMPQ    AX, R9
	CMOVQNE R11, R12
	NEGQ    R12
	ANDQ    R12, AX
	ANDQ    R12, R10
	SUBQ    R10, SI
	SUBQ    AX, DX
	SUBQ    AX, CX
	SUBQ    AX, R8
	SUBQ    AX, R9
	MOVQ    SI, 0(DI)
	MOVQ    DX, 8(DI)
	MOVQ    CX, 16(DI)
	MOVQ    R8, 24(DI)
	MOVQ    R9, 32(DI)
	RET

// func ladderstep(inout *[5][5]uint64)
TEXT ·ladderstep(SB), 0, $296-8
	MOVQ inout+0(FP), DI

	MOVQ   40(DI), SI
	MOVQ   48(DI), DX
	MOVQ   56(DI), CX
	MOVQ   64(DI), R8
	MOVQ   72(DI), R9
	MOVQ   SI, AX
	MOVQ   DX, R10
	MOVQ   CX, R11
	MOVQ   R8, R12
	MOVQ   R9, R13
	ADDQ   ·_2P0(SB), AX
	ADDQ   ·_2P1234(SB), R10
	ADDQ   ·_2P1234(SB), R11
	ADDQ   ·_2P1234(SB), R12
	ADDQ   ·_2P1234(SB), R13
	ADDQ   80(DI), SI
	ADDQ   88(DI), DX
	ADDQ   96(DI), CX
	ADDQ   104(DI), R8
	ADDQ   112(DI), R9
	SUBQ   80(DI), AX
	SUBQ   88(DI), R10
	SUBQ   96(DI), R11
	SUBQ   104(DI), R12
	SUBQ   112(DI), R13
	MOVQ   SI, 0(SP)
	MOVQ   DX, 8(SP)
	MOVQ   CX, 16(SP)
	MOVQ   R8, 24(SP)
	MOVQ   R9, 32(SP)
	MOVQ   AX, 40(SP)
	MOVQ   R10, 48(SP)
	MOVQ   R11, 56(SP)
	MOVQ   R12, 64(SP)
	MOVQ   R13, 72(SP)
	MOVQ   40(SP), AX
	MULQ   40(SP)
	MOVQ   AX, SI
	MOVQ   DX, CX
	MOVQ   40(SP), AX
	SHLQ   $1, AX
	MULQ   48(SP)
	MOVQ   AX, R8
	MOVQ   DX, R9
	MOVQ   40(SP), AX
	SHLQ   $1, AX
	MULQ   56(SP)
	MOVQ   AX, R10
	MOVQ   DX, R11
	MOVQ   40(SP), AX
	SHLQ   $1, AX
	MULQ   64(SP)
	MOVQ   AX, R12
	MOVQ   DX, R13
	MOVQ   40(SP), AX
	SHLQ   $1, AX
	MULQ   72(SP)
	MOVQ   AX, R14
	MOVQ   DX, R15
	MOVQ   48(SP), AX
	MULQ   48(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   48(SP), AX
	SHLQ   $1, AX
	MULQ   56(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   48(SP), AX
	SHLQ   $1, AX
	MULQ   64(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   48(SP), DX
	IMUL3Q $38, DX, AX
	MULQ   72(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   56(SP), AX
	MULQ   56(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   56(SP), DX
	IMUL3Q $38, DX, AX
	MULQ   64(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   56(SP), DX
	IMUL3Q $38, DX, AX
	MULQ   72(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   64(SP), DX
	IMUL3Q $19, DX, AX
	MULQ   64(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   64(SP), DX
	IMUL3Q $38, DX, AX
	MULQ   72(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   72(SP), DX
	IMUL3Q $19, DX, AX
	MULQ   72(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   $REDMASK51, DX
	SHLQ   $13, SI, CX
	ANDQ   DX, SI
	SHLQ   $13, R8, R9
	ANDQ   DX, R8
	ADDQ   CX, R8
	SHLQ   $13, R10, R11
	ANDQ   DX, R10
	ADDQ   R9, R10
	SHLQ   $13, R12, R13
	ANDQ   DX, R12
	ADDQ   R11, R12
	SHLQ   $13, R14, R15
	ANDQ   DX, R14
	ADDQ   R13, R14
	IMUL3Q $19, R15, CX
	ADDQ   CX, SI
	MOVQ   SI, CX
	SHRQ   $51, CX
	ADDQ   R8, CX
	ANDQ   DX, SI
	MOVQ   CX, R8
	SHRQ   $51, CX
	ADDQ   R10, CX
	ANDQ   DX, R8
	MOVQ   CX, R9
	SHRQ   $51, CX
	ADDQ   R12, CX
	ANDQ   DX, R9
	MOVQ   CX, AX
	SHRQ   $51, CX
	ADDQ   R14, CX
	ANDQ   DX, AX
	MOVQ   CX, R10
	SHRQ   $51, CX
	IMUL3Q $19, CX, CX
	ADDQ   CX, SI
	ANDQ   DX, R10
	MOVQ   SI, 80(SP)
	MOVQ   R8, 88(SP)
	MOVQ   R9, 96(SP)
	MOVQ   AX, 104(SP)
	MOVQ   R10, 112(SP)
	MOVQ   0(SP), AX
	MULQ   0(SP)
	MOVQ   AX, SI
	MOVQ   DX, CX
	MOVQ   0(SP), AX
	SHLQ   $1, AX
	MULQ   8(SP)
	MOVQ   AX, R8
	MOVQ   DX, R9
	MOVQ   0(SP), AX
	SHLQ   $1, AX
	MULQ   16(SP)
	MOVQ   AX, R10
	MOVQ   DX, R11
	MOVQ   0(SP), AX
	SHLQ   $1, AX
	MULQ   24(SP)
	MOVQ   AX, R12
	MOVQ   DX, R13
	MOVQ   0(SP), AX
	SHLQ   $1, AX
	MULQ   32(SP)
	MOVQ   AX, R14
	MOVQ   DX, R15
	MOVQ   8(SP), AX
	MULQ   8(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   8(SP), AX
	SHLQ   $1, AX
	MULQ   16(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   8(SP), AX
	SHLQ   $1, AX
	MULQ   24(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   8(SP), DX
	IMUL3Q $38, DX, AX
	MULQ   32(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   16(SP), AX
	MULQ   16(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   16(SP), DX
	IMUL3Q $38, DX, AX
	MULQ   24(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   16(SP), DX
	IMUL3Q $38, DX, AX
	MULQ   32(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   24(SP), DX
	IMUL3Q $19, DX, AX
	MULQ   24(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   24(SP), DX
	IMUL3Q $38, DX, AX
	MULQ   32(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   32(SP), DX
	IMUL3Q $19, DX, AX
	MULQ   32(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   $REDMASK51, DX
	SHLQ   $13, SI, CX
	ANDQ   DX, SI
	SHLQ   $13, R8, R9
	ANDQ   DX, R8
	ADDQ   CX, R8
	SHLQ   $13, R10, R11
	ANDQ   DX, R10
	ADDQ   R9, R10
	SHLQ   $13, R12, R13
	ANDQ   DX, R12
	ADDQ   R11, R12
	SHLQ   $13, R14, R15
	ANDQ   DX, R14
	ADDQ   R13, R14
	IMUL3Q $19, R15, CX
	ADDQ   CX, SI
	MOVQ   SI, CX
	SHRQ   $51, CX
	ADDQ   R8, CX
	ANDQ   DX, SI
	MOVQ   CX, R8
	SHRQ   $51, CX
	ADDQ   R10, CX
	ANDQ   DX, R8
	MOVQ   CX, R9
	SHRQ   $51, CX
	ADDQ   R12, CX
	ANDQ   DX, R9
	MOVQ   CX, AX
	SHRQ   $51, CX
	ADDQ   R14, CX
	ANDQ   DX, AX
	MOVQ   CX, R10
	SHRQ   $51, CX
	IMUL3Q $19, CX, CX
	ADDQ   CX, SI
	ANDQ   DX, R10
	MOVQ   SI, 120(SP)
	MOVQ   R8, 128(SP)
	MOVQ   R9, 136(SP)
	MOVQ   AX, 144(SP)
	MOVQ   R10, 152(SP)
	MOVQ   SI, SI
	MOVQ   R8, DX
	MOVQ   R9, CX
	MOVQ   AX, R8
	MOVQ   R10, R9
	ADDQ   ·_2P0(SB), SI
	ADDQ   ·_2P1234(SB), DX
	ADDQ   ·_2P1234(SB), CX
	ADDQ   ·_2P1234(SB), R8
	ADDQ   ·_2P1234(SB), R9
	SUBQ   80(SP), SI
	SUBQ   88(SP), DX
	SUBQ   96(SP), CX
	SUBQ   104(SP), R8
	SUBQ   112(SP), R9
	MOVQ   SI, 160(SP)
	MOVQ   DX, 168(SP)
	MOVQ   CX, 176(SP)
	MOVQ   R8, 184(SP)
	MOVQ   R9, 192(SP)
	MOVQ   120(DI), SI
	MOVQ   128(DI), DX
	MOVQ   136(DI), CX
	MOVQ   144(DI), R8
	MOVQ   152(DI), R9
	MOVQ   SI, AX
	MOVQ   DX, R10
	MOVQ   CX, R11
	MOVQ   R8, R12
	MOVQ   R9, R13
	ADDQ   ·_2P0(SB), AX
	ADDQ   ·_2P1234(SB), R10
	ADDQ   ·_2P1234(SB), R11
	ADDQ   ·_2P1234(SB), R12
	ADDQ   ·_2P1234(SB), R13
	ADDQ   160(DI), SI
	ADDQ   168(DI), DX
	ADDQ   176(DI), CX
	ADDQ   184(DI), R8
	ADDQ   192(DI), R9
	SUBQ   160(DI), AX
	SUBQ   168(DI), R10
	SUBQ   176(DI), R11
	SUBQ   184(DI), R12
	SUBQ   192(DI), R13
	MOVQ   SI, 200(SP)
	MOVQ   DX, 208(SP)
	MOVQ   CX, 216(SP)
	MOVQ   R8, 224(SP)
	MOVQ   R9, 232(SP)
	MOVQ   AX, 240(SP)
	MOVQ   R10, 248(SP)
	MOVQ   R11, 256(SP)
	MOVQ   R12, 264(SP)
	MOVQ   R13, 272(SP)
	MOVQ   224(SP), SI
	IMUL3Q $19, SI, AX
	MOVQ   AX, 280(SP)
	MULQ   56(SP)
	MOVQ   AX, SI
	MOVQ   DX, CX
	MOVQ   232(SP), DX
	IMUL3Q $19, DX, AX
	MOVQ   AX, 288(SP)
	MULQ   48(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   200(SP), AX
	MULQ   40(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   200(SP), AX
	MULQ   48(SP)
	MOVQ   AX, R8
	MOVQ   DX, R9
	MOVQ   200(SP), AX
	MULQ   56(SP)
	MOVQ   AX, R10
	MOVQ   DX, R11
	MOVQ   200(SP), AX
	MULQ   64(SP)
	MOVQ   AX, R12
	MOVQ   DX, R13
	MOVQ   200(SP), AX
	MULQ   72(SP)
	MOVQ   AX, R14
	MOVQ   DX, R15
	MOVQ   208(SP), AX
	MULQ   40(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   208(SP), AX
	MULQ   48(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   208(SP), AX
	MULQ   56(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   208(SP), AX
	MULQ   64(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   208(SP), DX
	IMUL3Q $19, DX, AX
	MULQ   72(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   216(SP), AX
	MULQ   40(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   216(SP), AX
	MULQ   48(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   216(SP), AX
	MULQ   56(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   216(SP), DX
	IMUL3Q $19, DX, AX
	MULQ   64(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   216(SP), DX
	IMUL3Q $19, DX, AX
	MULQ   72(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   224(SP), AX
	MULQ   40(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   224(SP), AX
	MULQ   48(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   280(SP), AX
	MULQ   64(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   280(SP), AX
	MULQ   72(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   232(SP), AX
	MULQ   40(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   288(SP), AX
	MULQ   56(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   288(SP), AX
	MULQ   64(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   288(SP), AX
	MULQ   72(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   $REDMASK51, DX
	SHLQ   $13, SI, CX
	ANDQ   DX, SI
	SHLQ   $13, R8, R9
	ANDQ   DX, R8
	ADDQ   CX, R8
	SHLQ   $13, R10, R11
	ANDQ   DX, R10
	ADDQ   R9, R10
	SHLQ   $13, R12, R13
	ANDQ   DX, R12
	ADDQ   R11, R12
	SHLQ   $13, R14, R15
	ANDQ   DX, R14
	ADDQ   R13, R14
	IMUL3Q $19, R15, CX
	ADDQ   CX, SI
	MOVQ   SI, CX
	SHRQ   $51, CX
	ADDQ   R8, CX
	MOVQ   CX, R8
	SHRQ   $51, CX
	ANDQ   DX, SI
	ADDQ   R10, CX
	MOVQ   CX, R9
	SHRQ   $51, CX
	ANDQ   DX, R8
	ADDQ   R12, CX
	MOVQ   CX, AX
	SHRQ   $51, CX
	ANDQ   DX, R9
	ADDQ   R14, CX
	MOVQ   CX, R10
	SHRQ   $51, CX
	ANDQ   DX, AX
	IMUL3Q $19, CX, CX
	ADDQ   CX, SI
	ANDQ   DX, R10
	MOVQ   SI, 40(SP)
	MOVQ   R8, 48(SP)
	MOVQ   R9, 56(SP)
	MOVQ   AX, 64(SP)
	MOVQ   R10, 72(SP)
	MOVQ   264(SP), SI
	IMUL3Q $19, SI, AX
	MOVQ   AX, 200(SP)
	MULQ   16(SP)
	MOVQ   AX, SI
	MOVQ   DX, CX
	MOVQ   272(SP), DX
	IMUL3Q $19, DX, AX
	MOVQ   AX, 208(SP)
	MULQ   8(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   240(SP), AX
	MULQ   0(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   240(SP), AX
	MULQ   8(SP)
	MOVQ   AX, R8
	MOVQ   DX, R9
	MOVQ   240(SP), AX
	MULQ   16(SP)
	MOVQ   AX, R10
	MOVQ   DX, R11
	MOVQ   240(SP), AX
	MULQ   24(SP)
	MOVQ   AX, R12
	MOVQ   DX, R13
	MOVQ   240(SP), AX
	MULQ   32(SP)
	MOVQ   AX, R14
	MOVQ   DX, R15
	MOVQ   248(SP), AX
	MULQ   0(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   248(SP), AX
	MULQ   8(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   248(SP), AX
	MULQ   16(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   248(SP), AX
	MULQ   24(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   248(SP), DX
	IMUL3Q $19, DX, AX
	MULQ   32(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   256(SP), AX
	MULQ   0(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   256(SP), AX
	MULQ   8(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   256(SP), AX
	MULQ   16(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   256(SP), DX
	IMUL3Q $19, DX, AX
	MULQ   24(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   256(SP), DX
	IMUL3Q $19, DX, AX
	MULQ   32(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   264(SP), AX
	MULQ   0(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   264(SP), AX
	MULQ   8(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   200(SP), AX
	MULQ   24(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   200(SP), AX
	MULQ   32(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   272(SP), AX
	MULQ   0(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   208(SP), AX
	MULQ   16(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   208(SP), AX
	MULQ   24(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   208(SP), AX
	MULQ   32(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   $REDMASK51, DX
	SHLQ   $13, SI, CX
	ANDQ   DX, SI
	SHLQ   $13, R8, R9
	ANDQ   DX, R8
	ADDQ   CX, R8
	SHLQ   $13, R10, R11
	ANDQ   DX, R10
	ADDQ   R9, R10
	SHLQ   $13, R12, R13
	ANDQ   DX, R12
	ADDQ   R11, R12
	SHLQ   $13, R14, R15
	ANDQ   DX, R14
	ADDQ   R13, R14
	IMUL3Q $19, R15, CX
	ADDQ   CX, SI
	MOVQ   SI, CX
	SHRQ   $51, CX
	ADDQ   R8, CX
	MOVQ   CX, R8
	SHRQ   $51, CX
	ANDQ   DX, SI
	ADDQ   R10, CX
	MOVQ   CX, R9
	SHRQ   $51, CX
	ANDQ   DX, R8
	ADDQ   R12, CX
	MOVQ   CX, AX
	SHRQ   $51, CX
	ANDQ   DX, R9
	ADDQ   R14, CX
	MOVQ   CX, R10
	SHRQ   $51, CX
	ANDQ   DX, AX
	IMUL3Q $19, CX, CX
	ADDQ   CX, SI
	ANDQ   DX, R10
	MOVQ   SI, DX
	MOVQ   R8, CX
	MOVQ   R9, R11
	MOVQ   AX, R12
	MOVQ   R10, R13
	ADDQ   ·_2P0(SB), DX
	ADDQ   ·_2P1234(SB), CX
	ADDQ   ·_2P1234(SB), R11
	ADDQ   ·_2P1234(SB), R12
	ADDQ   ·_2P1234(SB), R13
	ADDQ   40(SP), SI
	ADDQ   48(SP), R8
	ADDQ   56(SP), R9
	ADDQ   64(SP), AX
	ADDQ   72(SP), R10
	SUBQ   40(SP), DX
	SUBQ   48(SP), CX
	SUBQ   56(SP), R11
	SUBQ   64(SP), R12
	SUBQ   72(SP), R13
	MOVQ   SI, 120(DI)
	MOVQ   R8, 128(DI)
	MOVQ   R9, 136(DI)
	MOVQ   AX, 144(DI)
	MOVQ   R10, 152(DI)
	MOVQ   DX, 160(DI)
	MOVQ   CX, 168(DI)
	MOVQ   R11, 176(DI)
	MOVQ   R12, 184(DI)
	MOVQ   R13, 192(DI)
	MOVQ   120(DI), AX
	MULQ   120(DI)
	MOVQ   AX, SI
	MOVQ   DX, CX
	MOVQ   120(DI), AX
	SHLQ   $1, AX
	MULQ   128(DI)
	MOVQ   AX, R8
	MOVQ   DX, R9
	MOVQ   120(DI), AX
	SHLQ   $1, AX
	MULQ   136(DI)
	MOVQ   AX, R10
	MOVQ   DX, R11
	MOVQ   120(DI), AX
	SHLQ   $1, AX
	MULQ   144(DI)
	MOVQ   AX, R12
	MOVQ   DX, R13
	MOVQ   120(DI), AX
	SHLQ   $1, AX
	MULQ   152(DI)
	MOVQ   AX, R14
	MOVQ   DX, R15
	MOVQ   128(DI), AX
	MULQ   128(DI)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   128(DI), AX
	SHLQ   $1, AX
	MULQ   136(DI)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   128(DI), AX
	SHLQ   $1, AX
	MULQ   144(DI)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   128(DI), DX
	IMUL3Q $38, DX, AX
	MULQ   152(DI)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   136(DI), AX
	MULQ   136(DI)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   136(DI), DX
	IMUL3Q $38, DX, AX
	MULQ   144(DI)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   136(DI), DX
	IMUL3Q $38, DX, AX
	MULQ   152(DI)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   144(DI), DX
	IMUL3Q $19, DX, AX
	MULQ   144(DI)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   144(DI), DX
	IMUL3Q $38, DX, AX
	MULQ   152(DI)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   152(DI), DX
	IMUL3Q $19, DX, AX
	MULQ   152(DI)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   $REDMASK51, DX
	SHLQ   $13, SI, CX
	ANDQ   DX, SI
	SHLQ   $13, R8, R9
	ANDQ   DX, R8
	ADDQ   CX, R8
	SHLQ   $13, R10, R11
	ANDQ   DX, R10
	ADDQ   R9, R10
	SHLQ   $13, R12, R13
	ANDQ   DX, R12
	ADDQ   R11, R12
	SHLQ   $13, R14, R15
	ANDQ   DX, R14
	ADDQ   R13, R14
	IMUL3Q $19, R15, CX
	ADDQ   CX, SI
	MOVQ   SI, CX
	SHRQ   $51, CX
	ADDQ   R8, CX
	ANDQ   DX, SI
	MOVQ   CX, R8
	SHRQ   $51, CX
	ADDQ   R10, CX
	ANDQ   DX, R8
	MOVQ   CX, R9
	SHRQ   $51, CX
	ADDQ   R12, CX
	ANDQ   DX, R9
	MOVQ   CX, AX
	SHRQ   $51, CX
	ADDQ   R14, CX
	ANDQ   DX, AX
	MOVQ   CX, R10
	SHRQ   $51, CX
	IMUL3Q $19, CX, CX
	ADDQ   CX, SI
	ANDQ   DX, R10
	MOVQ   SI, 120(DI)
	MOVQ   R8, 128(DI)
	MOVQ   R9, 136(DI)
	MOVQ   AX, 144(DI)
	MOVQ   R10, 152(DI)
	MOVQ   160(DI), AX
	MULQ   160(DI)
	MOVQ   AX, SI
	MOVQ   DX, CX
	MOVQ   160(DI), AX
	SHLQ   $1, AX
	MULQ   168(DI)
	MOVQ   AX, R8
	MOVQ   DX, R9
	MOVQ   160(DI), AX
	SHLQ   $1, AX
	MULQ   176(DI)
	MOVQ   AX, R10
	MOVQ   DX, R11
	MOVQ   160(DI), AX
	SHLQ   $1, AX
	MULQ   184(DI)
	MOVQ   AX, R12
	MOVQ   DX, R13
	MOVQ   160(DI), AX
	SHLQ   $1, AX
	MULQ   192(DI)
	MOVQ   AX, R14
	MOVQ   DX, R15
	MOVQ   168(DI), AX
	MULQ   168(DI)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   168(DI), AX
	SHLQ   $1, AX
	MULQ   176(DI)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   168(DI), AX
	SHLQ   $1, AX
	MULQ   184(DI)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   168(DI), DX
	IMUL3Q $38, DX, AX
	MULQ   192(DI)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   176(DI), AX
	MULQ   176(DI)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   176(DI), DX
	IMUL3Q $38, DX, AX
	MULQ   184(DI)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   176(DI), DX
	IMUL3Q $38, DX, AX
	MULQ   192(DI)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   184(DI), DX
	IMUL3Q $19, DX, AX
	MULQ   184(DI)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   184(DI), DX
	IMUL3Q $38, DX, AX
	MULQ   192(DI)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   192(DI), DX
	IMUL3Q $19, DX, AX
	MULQ   192(DI)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   $REDMASK51, DX
	SHLQ   $13, SI, CX
	ANDQ   DX, SI
	SHLQ   $13, R8, R9
	ANDQ   DX, R8
	ADDQ   CX, R8
	SHLQ   $13, R10, R11
	ANDQ   DX, R10
	ADDQ   R9, R10
	SHLQ   $13, R12, R13
	ANDQ   DX, R12
	ADDQ   R11, R12
	SHLQ   $13, R14, R15
	ANDQ   DX, R14
	ADDQ   R13, R14
	IMUL3Q $19, R15, CX
	ADDQ   CX, SI
	MOVQ   SI, CX
	SHRQ   $51, CX
	ADDQ   R8, CX
	ANDQ   DX, SI
	MOVQ   CX, R8
	SHRQ   $51, CX
	ADDQ   R10, CX
	ANDQ   DX, R8
	MOVQ   CX, R9
	SHRQ   $51, CX
	ADDQ   R12, CX
	ANDQ   DX, R9
	MOVQ   CX, AX
	SHRQ   $51, CX
	ADDQ   R14, CX
	ANDQ   DX, AX
	MOVQ   CX, R10
	SHRQ   $51, CX
	IMUL3Q $19, CX, CX
	ADDQ   CX, SI
	ANDQ   DX, R10
	MOVQ   SI, 160(DI)
	MOVQ   R8, 168(DI)
	MOVQ   R9, 176(DI)
	MOVQ   AX, 184(DI)
	MOVQ   R10, 192(DI)
	MOVQ   184(DI), SI
	IMUL3Q $19, SI, AX
	MOVQ   AX, 0(SP)
	MULQ   16(DI)
	MOVQ   AX, SI
	MOVQ   DX, CX
	MOVQ   192(DI), DX
	IMUL3Q $19, DX, AX
	MOVQ   AX, 8(SP)
	MULQ   8(DI)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   160(DI), AX
	MULQ   0(DI)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   160(DI), AX
	MULQ   8(DI)
	MOVQ   AX, R8
	MOVQ   DX, R9
	MOVQ   160(DI), AX
	MULQ   16(DI)
	MOVQ   AX, R10
	MOVQ   DX, R11
	MOVQ   160(DI), AX
	MULQ   24(DI)
	MOVQ   AX, R12
	MOVQ   DX, R13
	MOVQ   160(DI), AX
	MULQ   32(DI)
	MOVQ   AX, R14
	MOVQ   DX, R15
	MOVQ   168(DI), AX
	MULQ   0(DI)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   168(DI), AX
	MULQ   8(DI)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   168(DI), AX
	MULQ   16(DI)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   168(DI), AX
	MULQ   24(DI)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   168(DI), DX
	IMUL3Q $19, DX, AX
	MULQ   32(DI)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   176(DI), AX
	MULQ   0(DI)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   176(DI), AX
	MULQ   8(DI)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   176(DI), AX
	MULQ   16(DI)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   176(DI), DX
	IMUL3Q $19, DX, AX
	MULQ   24(DI)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   176(DI), DX
	IMUL3Q $19, DX, AX
	MULQ   32(DI)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   184(DI), AX
	MULQ   0(DI)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   184(DI), AX
	MULQ   8(DI)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   0(SP), AX
	MULQ   24(DI)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   0(SP), AX
	MULQ   32(DI)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   192(DI), AX
	MULQ   0(DI)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   8(SP), AX
	MULQ   16(DI)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   8(SP), AX
	MULQ   24(DI)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   8(SP), AX
	MULQ   32(DI)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   $REDMASK51, DX
	SHLQ   $13, SI, CX
	ANDQ   DX, SI
	SHLQ   $13, R8, R9
	ANDQ   DX, R8
	ADDQ   CX, R8
	SHLQ   $13, R10, R11
	ANDQ   DX, R10
	ADDQ   R9, R10
	SHLQ   $13, R12, R13
	ANDQ   DX, R12
	ADDQ   R11, R12
	SHLQ   $13, R14, R15
	ANDQ   DX, R14
	ADDQ   R13, R14
	IMUL3Q $19, R15, CX
	ADDQ   CX, SI
	MOVQ   SI, CX
	SHRQ   $51, CX
	ADDQ   R8, CX
	MOVQ   CX, R8
	SHRQ   $51, CX
	ANDQ   DX, SI
	ADDQ   R10, CX
	MOVQ   CX, R9
	SHRQ   $51, CX
	ANDQ   DX, R8
	ADDQ   R12, CX
	MOVQ   CX, AX
	SHRQ   $51, CX
	ANDQ   DX, R9
	ADDQ   R14, CX
	MOVQ   CX, R10
	SHRQ   $51, CX
	ANDQ   DX, AX
	IMUL3Q $19, CX, CX
	ADDQ   CX, SI
	ANDQ   DX, R10
	MOVQ   SI, 160(DI)
	MOVQ   R8, 168(DI)
	MOVQ   R9, 176(DI)
	MOVQ   AX, 184(DI)
	MOVQ   R10, 192(DI)
	MOVQ   144(SP), SI
	IMUL3Q $19, SI, AX
	MOVQ   AX, 0(SP)
	MULQ   96(SP)
	MOVQ   AX, SI
	MOVQ   DX, CX
	MOVQ   152(SP), DX
	IMUL3Q $19, DX, AX
	MOVQ   AX, 8(SP)
	MULQ   88(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   120(SP), AX
	MULQ   80(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   120(SP), AX
	MULQ   88(SP)
	MOVQ   AX, R8
	MOVQ   DX, R9
	MOVQ   120(SP), AX
	MULQ   96(SP)
	MOVQ   AX, R10
	MOVQ   DX, R11
	MOVQ   120(SP), AX
	MULQ   104(SP)
	MOVQ   AX, R12
	MOVQ   DX, R13
	MOVQ   120(SP), AX
	MULQ   112(SP)
	MOVQ   AX, R14
	MOVQ   DX, R15
	MOVQ   128(SP), AX
	MULQ   80(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   128(SP), AX
	MULQ   88(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   128(SP), AX
	MULQ   96(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   128(SP), AX
	MULQ   104(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   128(SP), DX
	IMUL3Q $19, DX, AX
	MULQ   112(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   136(SP), AX
	MULQ   80(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   136(SP), AX
	MULQ   88(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   136(SP), AX
	MULQ   96(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   136(SP), DX
	IMUL3Q $19, DX, AX
	MULQ   104(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   136(SP), DX
	IMUL3Q $19, DX, AX
	MULQ   112(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   144(SP), AX
	MULQ   80(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   144(SP), AX
	MULQ   88(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   0(SP), AX
	MULQ   104(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   0(SP), AX
	MULQ   112(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   152(SP), AX
	MULQ   80(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   8(SP), AX
	MULQ   96(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   8(SP), AX
	MULQ   104(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   8(SP), AX
	MULQ   112(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   $REDMASK51, DX
	SHLQ   $13, SI, CX
	ANDQ   DX, SI
	SHLQ   $13, R8, R9
	ANDQ   DX, R8
	ADDQ   CX, R8
	SHLQ   $13, R10, R11
	ANDQ   DX, R10
	ADDQ   R9, R10
	SHLQ   $13, R12, R13
	ANDQ   DX, R12
	ADDQ   R11, R12
	SHLQ   $13, R14, R15
	ANDQ   DX, R14
	ADDQ   R13, R14
	IMUL3Q $19, R15, CX
	ADDQ   CX, SI
	MOVQ   SI, CX
	SHRQ   $51, CX
	ADDQ   R8, CX
	MOVQ   CX, R8
	SHRQ   $51, CX
	ANDQ   DX, SI
	ADDQ   R10, CX
	MOVQ   CX, R9
	SHRQ   $51, CX
	ANDQ   DX, R8
	ADDQ   R12, CX
	MOVQ   CX, AX
	SHRQ   $51, CX
	ANDQ   DX, R9
	ADDQ   R14, CX
	MOVQ   CX, R10
	SHRQ   $51, CX
	ANDQ   DX, AX
	IMUL3Q $19, CX, CX
	ADDQ   CX, SI
	ANDQ   DX, R10
	MOVQ   SI, 40(DI)
	MOVQ   R8, 48(DI)
	MOVQ   R9, 56(DI)
	MOVQ   AX, 64(DI)
	MOVQ   R10, 72(DI)
	MOVQ   160(SP), AX
	MULQ   ·_121666_213(SB)
	SHRQ   $13, AX
	MOVQ   AX, SI
	MOVQ   DX, CX
	MOVQ   168(SP), AX
	MULQ   ·_121666_213(SB)
	SHRQ   $13, AX
	ADDQ   AX, CX
	MOVQ   DX, R8
	MOVQ   176(SP), AX
	MULQ   ·_121666_213(SB)
	SHRQ   $13, AX
	ADDQ   AX, R8
	MOVQ   DX, R9
	MOVQ   184(SP), AX
	MULQ   ·_121666_213(SB)
	SHRQ   $13, AX
	ADDQ   AX, R9
	MOVQ   DX, R10
	MOVQ   192(SP), AX
	MULQ   ·_121666_213(SB)
	SHRQ   $13, AX
	ADDQ   AX, R10
	IMUL3Q $19, DX, DX
	ADDQ   DX, SI
	ADDQ   80(SP), SI
	ADDQ   88(SP), CX
	ADDQ   96(SP), R8
	ADDQ   104(SP), R9
	ADDQ   112(SP), R10
	MOVQ   SI, 80(DI)
	MOVQ   CX, 88(DI)
	MOVQ   R8, 96(DI)
	MOVQ   R9, 104(DI)
	MOVQ   R10, 112(DI)
	MOVQ   104(DI), SI
	IMUL3Q $19, SI, AX
	MOVQ   AX, 0(SP)
	MULQ   176(SP)
	MOVQ   AX, SI
	MOVQ   DX, CX
	MOVQ   112(DI), DX
	IMUL3Q $19, DX, AX
	MOVQ   AX, 8(SP)
	MULQ   168(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   80(DI), AX
	MULQ   160(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   80(DI), AX
	MULQ   168(SP)
	MOVQ   AX, R8
	MOVQ   DX, R9
	MOVQ   80(DI), AX
	MULQ   176(SP)
	MOVQ   AX, R10
	MOVQ   DX, R11
	MOVQ   80(DI), AX
	MULQ   184(SP)
	MOVQ   AX, R12
	MOVQ   DX, R13
	MOVQ   80(DI), AX
	MULQ   192(SP)
	MOVQ   AX, R14
	MOVQ   DX, R15
	MOVQ   88(DI), AX
	MULQ   160(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   88(DI), AX
	MULQ   168(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   88(DI), AX
	MULQ   176(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   88(DI), AX
	MULQ   184(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   88(DI), DX
	IMUL3Q $19, DX, AX
	MULQ   192(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   96(DI), AX
	MULQ   160(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   96(DI), AX
	MULQ   168(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   96(DI), AX
	MULQ   176(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   96(DI), DX
	IMUL3Q $19, DX, AX
	MULQ   184(SP)
	ADDQ   AX, SI
	ADCQ   DX, CX
	MOVQ   96(DI), DX
	IMUL3Q $19, DX, AX
	MULQ   192(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   104(DI), AX
	MULQ   160(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   104(DI), AX
	MULQ   168(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   0(SP), AX
	MULQ   184(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   0(SP), AX
	MULQ   192(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   112(DI), AX
	MULQ   160(SP)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   8(SP), AX
	MULQ   176(SP)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   8(SP), AX
	MULQ   184(SP)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   8(SP), AX
	MULQ   192(SP)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   $REDMASK51, DX
	SHLQ   $13, SI, CX
	ANDQ   DX, SI
	SHLQ   $13, R8, R9
	ANDQ   DX, R8
	ADDQ   CX, R8
	SHLQ   $13, R10, R11
	ANDQ   DX, R10
	ADDQ   R9, R10
	SHLQ   $13, R12, R13
	ANDQ   DX, R12
	ADDQ   R11, R12
	SHLQ   $13, R14, R15
	ANDQ   DX, R14
	ADDQ   R13, R14
	IMUL3Q $19, R15, CX
	ADDQ   CX, SI
	MOVQ   SI, CX
	SHRQ   $51, CX
	ADDQ   R8, CX
	MOVQ   CX, R8
	SHRQ   $51, CX
	ANDQ   DX, SI
	ADDQ   R10, CX
	MOVQ   CX, R9
	SHRQ   $51, CX
	ANDQ   DX, R8
	ADDQ   R12, CX
	MOVQ   CX, AX
	SHRQ   $51, CX
	ANDQ   DX, R9
	ADDQ   R14, CX
	MOVQ   CX, R10
	SHRQ   $51, CX
	ANDQ   DX, AX
	IMUL3Q $19, CX, CX
	ADDQ   CX, SI
	ANDQ   DX, R10
	MOVQ   SI, 80(DI)
	MOVQ   R8, 88(DI)
	MOVQ   R9, 96(DI)
	MOVQ   AX, 104(DI)
	MOVQ   R10, 112(DI)
	RET

// func cswap(inout *[4][5]uint64, v uint64)
TEXT ·cswap(SB), 7, $0
	MOVQ inout+0(FP), DI
	MOVQ v+8(FP), SI

	SUBQ   $1, SI
	NOTQ   SI
	MOVQ   SI, X15
	PSHUFD $0x44, X15, X15

	MOVOU 0(DI), X0
	MOVOU 16(DI), X2
	MOVOU 32(DI), X4
	MOVOU 48(DI), X6
	MOVOU 64(DI), X8
	MOVOU 80(DI), X1
	MOVOU 96(DI), X3
	MOVOU 112(DI), X5
	MOVOU 128(DI), X7
	MOVOU 144(DI), X9

	MOVO X1, X10
	MOVO X3, X11
	MOVO X5, X12
	MOVO X7, X13
	MOVO X9, X14

	PXOR X0, X10
	PXOR X2, X11
	PXOR X4, X12
	PXOR X6, X13
	PXOR X8, X14
	PAND X15, X10
	PAND X15, X11
	PAND X15, X12
	PAND X15, X13
	PAND X15, X14
	PXOR X10, X0
	PXOR X10, X1
	PXOR X11, X2
	PXOR X11, X3
	PXOR X12, X4
	PXOR X12, X5
	PXOR X13, X6
	PXOR X13, X7
	PXOR X14, X8
	PXOR X14, X9

	MOVOU X0, 0(DI)
	MOVOU X2, 16(DI)
	MOVOU X4, 32(DI)
	MOVOU X6, 48(DI)
	MOVOU X8, 64(DI)
	MOVOU X1, 80(DI)
	MOVOU X3, 96(DI)
	MOVOU X5, 112(DI)
	MOVOU X7, 128(DI)
	MOVOU X9, 144(DI)
	RET

// func mul(outp *uint64, xp *uint64, yp *uint64)
TEXT ·mul(SB), NOSPLIT, $0
	MOVQ outp+0(FP), DI
	MOVQ xp+8(FP), BX
	MOVQ yp+16(FP), CX

	// Calculate r0
	MOVQ   0(BX), AX   // rax <-- x0
	MULQ   0(CX)       // rdx, rax <-- x0*y0
	MOVQ   AX, SI      // r00 = rax
	MOVQ   DX, BP      // r01 = rdx
	MOVQ   8(BX), DX   // rdx <-- x1
	IMUL3Q $19, DX, AX // rax <-- x1*19
	MULQ   32(CX)      // rdx, rax <-- x1_19*y4
	ADDQ   AX, SI      // r00 += rax
	ADCQ   DX, BP      // r01 += rdx
	MOVQ   16(BX), DX  // rdx <-- x2
	IMUL3Q $19, DX, AX // rax <-- x2*19
	MULQ   24(CX)      // rdx, rax <-- x2_19*y3
	ADDQ   AX, SI      // r00 += rax
	ADCQ   DX, BP      // r01 += rdx
	MOVQ   24(BX), DX  // rdx <-- x3
	IMUL3Q $19, DX, AX // rax <-- x3*19
	MULQ   16(CX)      // rdx, rax <-- x3_19 * y2
	ADDQ   AX, SI      // r00 += rax
	ADCQ   DX, BP      // r01 += rdx
	MOVQ   32(BX), DX  // rdx <-- x4
	IMUL3Q $19, DX, AX // rax <-- x4*19
	MULQ   8(CX)       // rdx rax <-- x4_19*y1
	ADDQ   AX, SI      // r00 += rax
	ADCQ   DX, BP      // r01 += rdx

	// Calculate r1
	MOVQ   0(BX), AX
	MULQ   8(CX)
	MOVQ   AX, R8      // r10
	MOVQ   DX, R9      // r11
	MOVQ   8(BX), AX
	MULQ   0(CX)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   16(BX), DX
	IMUL3Q $19, DX, AX
	MULQ   32(CX)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   24(BX), DX
	IMUL3Q $19, DX, AX
	MULQ   24(CX)
	ADDQ   AX, R8
	ADCQ   DX, R9
	MOVQ   32(BX), DX
	IMUL3Q $19, DX, AX
	MULQ   16(CX)
	ADDQ   AX, R8
	ADCQ   DX, R9

	// Calculate r2
	MOVQ   0(BX), AX
	MULQ   16(CX)
	MOVQ   AX, R10     // r20
	MOVQ   DX, R11     // r21
	MOVQ   8(BX), AX
	MULQ   8(CX)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   16(BX), AX
	MULQ   0(CX)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   24(BX), DX
	IMUL3Q $19, DX, AX
	MULQ   32(CX)
	ADDQ   AX, R10
	ADCQ   DX, R11
	MOVQ   32(BX), DX
	IMUL3Q $19, DX, AX
	MULQ   24(CX)
	ADDQ   AX, R10
	ADCQ   DX, R11

	// Calculate r3
	MOVQ   0(BX), AX
	MULQ   24(CX)
	MOVQ   AX, R12     // r30
	MOVQ   DX, R13     // r31
	MOVQ   8(BX), AX
	MULQ   16(CX)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   16(BX), AX
	MULQ   8(CX)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   24(BX), AX
	MULQ   0(CX)
	ADDQ   AX, R12
	ADCQ   DX, R13
	MOVQ   32(BX), DX
	IMUL3Q $19, DX, AX
	MULQ   32(CX)
	ADDQ   AX, R12
	ADCQ   DX, R13

	// Calculate r4
	MOVQ   0(BX), AX
	MULQ   32(CX)
	MOVQ   AX, R14               // r40
	MOVQ   DX, R15               // r41
	MOVQ   8(BX), AX
	MULQ   24(CX)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   16(BX), AX
	MULQ   16(CX)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   24(BX), AX
	MULQ   8(CX)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   32(BX), AX
	MULQ   0(CX)
	ADDQ   AX, R14
	ADCQ   DX, R15
	MOVQ   $2251799813685247, AX // (1<<51) - 1
	SHLQ   $13, SI, BP           // r01 = shld with r00
	ANDQ   AX, SI                // r00 &= mask51
	SHLQ   $13, R8, R9           // r11 = shld with r10
	ANDQ   AX, R8                // r10 &= mask51
	ADDQ   BP, R8                // r10 += r01
	SHLQ   $13, R10, R11         // r21 = shld with r20
	ANDQ   AX, R10               // r20 &= mask51
	ADDQ   R9, R10               // r20 += r11
	SHLQ   $13, R12, R13         // r31 = shld with r30
	ANDQ   AX, R12               // r30 &= mask51
	ADDQ   R11, R12              // r30 += r21
	SHLQ   $13, R14, R15         // r41 = shld with r40
	ANDQ   AX, R14               // r40 &= mask51
	ADDQ   R13, R14              // r40 += r31
	IMUL3Q $19, R15, R15         // r41 = r41*19
	ADDQ   R15, SI               // r00 += r41
	MOVQ   SI, DX                // rdx <-- r00
	SHRQ   $51, DX               // rdx <-- r00 >> 51
	ADDQ   DX, R8                // r10 += r00 >> 51
	MOVQ   R8, DX                // rdx <-- r10
	SHRQ   $51, DX               // rdx <-- r10 >> 51
	ANDQ   AX, SI                // r00 &= mask51
	ADDQ   DX, R10               // r20 += r10 >> 51
	MOVQ   R10, DX               // rdx <-- r20
	SHRQ   $51, DX               // rdx <-- r20 >> 51
	ANDQ   AX, R8                // r10 &= mask51
	ADDQ   DX, R12               // r30 += r20 >> 51
	MOVQ   R12, DX               // rdx <-- r30
	SHRQ   $51, DX               // rdx <-- r30 >> 51
	ANDQ   AX, R10               // r20 &= mask51
	ADDQ   DX, R14               // r40 += r30 >> 51
	MOVQ   R14, DX               // rdx <-- r40
	SHRQ   $51, DX               // rdx <-- r40 >> 51
	ANDQ   AX, R12               // r30 &= mask51
	IMUL3Q $19, DX, DX           // rdx <-- (r40 >> 51) * 19
	ADDQ   DX, SI                // r00 += (r40 >> 51) *19
	ANDQ   AX, R14               // r40 &= mask51
	MOVQ   SI, 0(DI)
	MOVQ   R8, 8(DI)
	MOVQ   R10, 16(DI)
	MOVQ   R12, 24(DI)
	MOVQ   R14, 32(DI)
	RET

// func square(outp *uint64, xp *uint64)
TEXT ·square(SB), NOSPLIT, $0
	MOVQ outp+0(FP), DI
	MOVQ xp+8(FP), SI

	// r0 = x0*x0 + x1*38*x4 + x2*38*x3
	MOVQ   0(SI), AX
	MULQ   0(SI)
	MOVQ   AX, CX      // r00
	MOVQ   DX, R8      // r01
	MOVQ   8(SI), DX
	IMUL3Q $38, DX, AX
	MULQ   32(SI)
	ADDQ   AX, CX
	ADCQ   DX, R8
	MOVQ   16(SI), DX
	IMUL3Q $38, DX, AX
	MULQ   24(SI)
	ADDQ   AX, CX
	ADCQ   DX, R8

	// r1 = x0*2*x1 + x2*38*x4 + x3*19*x3
	MOVQ   0(SI), AX
	SHLQ   $1, AX
	MULQ   8(SI)
	MOVQ   AX, R9      // r10
	MOVQ   DX, R10     // r11
	MOVQ   16(SI), DX
	IMUL3Q $38, DX, AX
	MULQ   32(SI)
	ADDQ   AX, R9
	ADCQ   DX, R10
	MOVQ   24(SI), DX
	IMUL3Q $19, DX, AX
	MULQ   24(SI)
	ADDQ   AX, R9
	ADCQ   DX, R10

	// r2 = x0*2*x2 + x1*x1 + x3*38*x4
	MOVQ   0(SI), AX
	SHLQ   $1, AX
	MULQ   16(SI)
	MOVQ   AX, R11     // r20
	MOVQ   DX, R12     // r21
	MOVQ   8(SI), AX
	MULQ   8(SI)
	ADDQ   AX, R11
	ADCQ   DX, R12
	MOVQ   24(SI), DX
	IMUL3Q $38, DX, AX
	MULQ   32(SI)
	ADDQ   AX, R11
	ADCQ   DX, R12

	// r3 = x0*2*x3 + x1*2*x2 + x4*19*x4
	MOVQ   0(SI), AX
	SHLQ   $1, AX
	MULQ   24(SI)
	MOVQ   AX, R13     // r30
	MOVQ   DX, R14     // r31
	MOVQ   8(SI), AX
	SHLQ   $1, AX
	MULQ   16(SI)
	ADDQ   AX, R13
	ADCQ   DX, R14
	MOVQ   32(SI), DX
	IMUL3Q $19, DX, AX
	MULQ   32(SI)
	ADDQ   AX, R13
	ADCQ   DX, R14

	// r4 = x0*2*x4 + x1*2*x3 + x2*x2
	MOVQ 0(SI), AX
	SHLQ $1, AX
	MULQ 32(SI)
	MOVQ AX, R15    // r40
	MOVQ DX, BX     // r41
	MOVQ 8(SI), AX
	SHLQ $1, AX
	MULQ 24(SI)
	ADDQ AX, R15
	ADCQ DX, BX
	MOVQ 16(SI), AX
	MULQ 16(SI)
	ADDQ AX, R15
	ADCQ DX, BX

	// Reduce
	MOVQ   $2251799813685247, AX // (1<<51) - 1
	SHLQ   $13, CX, R8           // r01 = shld with r00
	ANDQ   AX, CX                // r00 &= mask51
	SHLQ   $13, R9, R10          // r11 = shld with r10
	ANDQ   AX, R9                // r10 &= mask51
	ADDQ   R8, R9                // r10 += r01
	SHLQ   $13, R11, R12         // r21 = shld with r20
	ANDQ   AX, R11               // r20 &= mask51
	ADDQ   R10, R11              // r20 += r11
	SHLQ   $13, R13, R14         // r31 = shld with r30
	ANDQ   AX, R13               // r30 &= mask51
	ADDQ   R12, R13              // r30 += r21
	SHLQ   $13, R15, BX          // r41 = shld with r40
	ANDQ   AX, R15               // r40 &= mask51
	ADDQ   R14, R15              // r40 += r31
	IMUL3Q $19, BX, DX           // r41 = r41*19
	ADDQ   DX, CX                // r00 += r41
	MOVQ   CX, DX                // rdx <-- r00
	SHRQ   $51, DX               // rdx <-- r00 >> 51
	ADDQ   DX, R9                // r10 += r00 >> 51
	MOVQ   R9, DX                // rdx <-- r10
	SHRQ   $51, DX               // rdx <-- r10 >> 51
	ANDQ   AX, CX                // r00 &= mask51
	ADDQ   DX, R11               // r20 += r10 >> 51
	MOVQ   R11, DX               // rdx <-- r20
	SHRQ   $51, DX               // rdx <-- r20 >> 51
	ANDQ   AX, R9                // r10 &= mask51
	ADDQ   DX, R13               // r30 += r20 >> 51
	MOVQ   R13, DX               // rdx <-- r30
	SHRQ   $51, DX               // rdx <-- r30 >> 51
	ANDQ   AX, R11               // r20 &= mask51
	ADDQ   DX, R15               // r40 += r30 >> 51
	MOVQ   R15, DX               // rdx <-- r40
	SHRQ   $51, DX               // rdx <-- r40 >> 51
	ANDQ   AX, R13               // r30 &= mask51
	IMUL3Q $19, DX, DX           // rdx <-- (r40 >> 51) * 19
	ADDQ   DX, CX                // r00 += (r40 >> 51) *19
	ANDQ   AX, R15               // r40 &= mask51
	MOVQ   CX, 0(DI)
	MOVQ   R9, 8(DI)
	MOVQ   R11, 16(DI)
	MOVQ   R13, 24(DI)
	MOVQ   R15, 32(DI)
	RET
