// Copyright 2020 Jeffrey H. Johnson.
// Copyright 2020 Gridfinity, LLC.
// Copyright 2019 The Go Authors.
// All rights reserved.
// Use of this source code is governed by the BSD-style
// license that can be found in the LICENSE file.

package OldCurve25519ScalarMult

import (
	"fmt"
	mrand "math/rand"
	"testing"
	"time"
)

func benchmarkOldScalarBaseMult(x int, b *testing.B) {
	var in, out [X25519Size]byte
	for bSetup := 0; bSetup < 32; bSetup = (bSetup + 2) {
		in[bSetup] = ((byte(bSetup) + 1) + byte(x))
		in[bSetup+1] = (in[bSetup] + byte(x))
	}
	var err error
	b.SetBytes(X25519Size)
	for i := 0; i < b.N; i++ {
		err = OldScalarBaseMult(&out, &in)
		if err != nil {
			b.Fatal(
				fmt.Sprintf(
					"benchmarkOldScalarBaseMult.OldScalarBaseMult failure: %v: input=%v, output=%v",
					err,
					in,
					out,
				),
			)
		}
	}
	Basepoint = out
	err = oldScalarVerifyBasepoint(Basepoint)
	if err == nil {
		b.Fatal(
			fmt.Sprintf(
				"benchmarkOldScalarBaseMult.oldScalarVerifyBasepoint failure: %v",
				err,
			),
		)
	}
}

func BenchmarkOldScalarBaseMult_01(b *testing.B) {
	mrand.Seed(time.Now().UnixNano())
	z := mrand.Intn((((1 << 8) - 1 - 1) - 1) + 1)
	benchmarkOldScalarBaseMult(z, b)
}

func BenchmarkOldScalarBaseMult_02(b *testing.B) {
	mrand.Seed(time.Now().UnixNano())
	z := mrand.Intn((((1 << 8) - 2 - 1) - 2) + 2)
	benchmarkOldScalarBaseMult(z+2, b)
}

func BenchmarkOldScalarBaseMult_04(b *testing.B) {
	mrand.Seed(time.Now().UnixNano())
	z := mrand.Intn((((1 << 8) - 4 - 1) - 4) + 4)
	benchmarkOldScalarBaseMult(z+4, b)
}

func BenchmarkOldScalarBaseMult_08(b *testing.B) {
	mrand.Seed(time.Now().UnixNano())
	z := mrand.Intn((((1 << 8) - 8 - 1) - 8) + 8)
	benchmarkOldScalarBaseMult(z+8, b)
}

func BenchmarkOldScalarBaseMult_16(b *testing.B) {
	mrand.Seed(time.Now().UnixNano())
	z := mrand.Intn((((1 << 8) - 16 - 1) - 16) + 16)
	benchmarkOldScalarBaseMult(z+16, b)
}

func BenchmarkOldScalarBaseMult_32(b *testing.B) {
	mrand.Seed(time.Now().UnixNano())
	z := mrand.Intn((((1 << 8) - 32 - 1) - 32) + 32)
	benchmarkOldScalarBaseMult(z+32, b)
}
