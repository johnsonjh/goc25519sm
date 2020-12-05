// Copyright 2020 Jeffrey H. Johnson.
// Copyright 2020 Gridfinity, LLC.
// Copyright 2020 Frank Denis <j at pureftpd dot org>.
// Copyright 2012 The Go Authors.
// All rights reserved.
// Use of this source code is governed by the BSD-style
// license that can be found in the LICENSE file.

package goc25519sm_test

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"testing"

	goc25519sm "github.com/johnsonjh/goc25519sm"
	leak "go.uber.org/goleak"
)

const (
	expectedHex = "89161fde887b2b53de549af483940106ecc114d6982daa98256de23bdf77661a"
)

var lowOrderPoints = [][goc25519sm.X25519Size]byte{
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	},

	{
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	},

	{
		0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
		0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
		0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
		0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
	},

	{
		0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24,
		0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
		0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86,
		0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
	},

	{
		0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	},

	{
		0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	},

	{
		0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	},
}

var curved25519Expected = [goc25519sm.X25519Size]byte{
	0xac, 0xce, 0x24, 0xb1, 0xd4, 0xa2, 0x36, 0x21,
	0x15, 0xe2, 0x3e, 0x84, 0x3c, 0x23, 0x2b, 0x5f,
	0x95, 0x6c, 0xc0, 0x7b, 0x95, 0x82, 0xd7, 0x93,
	0xd5, 0x19, 0xb6, 0xf1, 0xfb, 0x96, 0xd6, 0x04,
}

func TestTestVectors(t *testing.T) {
	defer leak.VerifyNone(t)
	t.Run(
		"PureGo",
		func(t *testing.T) { testTestVectors(t, goc25519sm.OldScalarMultGeneric) },
	)
	t.Run(
		"Native",
		func(t *testing.T) { testTestVectors(t, goc25519sm.OldScalarMult) },
	)
}

func testTestVectors(
	t *testing.T,
	OldScalarMult func(dst, scalar, point *[goc25519sm.X25519Size]byte) error,
) {
	defer leak.VerifyNone(t)
	for _, tv := range testVectors {
		var got [goc25519sm.X25519Size]byte
		goc25519sm.OldScalarMult(&got, &tv.In, &tv.Base)
		if !bytes.Equal(got[:], tv.Expect[:]) {
			t.Logf("    in = %x", tv.In)
			t.Logf("  base = %x", tv.Base)
			t.Logf("   got = %x", got)
			t.Logf("expect = %x", tv.Expect)
			t.Fail()
		}
	}
}

// TestHighBitIgnored tests the following requirement in RFC-7748:
//  "When receiving such an array, implementations of X25519
//   ... MUST mask the most significant bit in the final byte."
func TestHighBitIgnored(t *testing.T) {
	defer leak.VerifyNone(t)
	var err error = fmt.Errorf("err never returned")
	var s, u [goc25519sm.X25519Size]byte
	crand.Read(s[:])
	crand.Read(u[:])
	var hi0, hi1 [goc25519sm.X25519Size]byte
	u[31] &= 0x7f
	err = goc25519sm.OldScalarMult(&hi0, &s, &u)
	if err != nil {
		t.Errorf(
			"goc25519sm.TestHighBitIgnored.OldScalarMult failure: %v",
			err,
		)
	} else {
		err = fmt.Errorf("err never returned")
	}
	u[31] |= 0x80
	err = goc25519sm.OldScalarMult(&hi1, &s, &u)
	if err != nil {
		t.Errorf(
			"goc25519sm.TestHighBitIgnored.OldScalarMult faulure: %v",
			err,
		)
	}
	if !bytes.Equal(hi0[:], hi1[:]) {
		t.Errorf(
			"goc25519sm.TestHighBitIgnored failure: high bit of group point affecting result",
		)
	}
}

func TestOldScalarBaseMult1024(t *testing.T) {
	defer leak.VerifyNone(t)
	var err error = fmt.Errorf("err never returned")
	csk := [2][goc25519sm.X25519Size]byte{
		{255},
	}
	for i := 0; i < 1024; i++ {
		err = goc25519sm.OldScalarBaseMult(&csk[(i&1)^1], &csk[i&1])
		if err != nil {
			t.Errorf(
				"goc25519sm.TestOldScalarBaseMult1024.OldScalarBaseMult failure: %v",
				err,
			)
		}
	}
	if !bytes.Equal(curved25519Expected[:], csk[0][:]) {
		t.Fatal(
			"goc25519sm.TestOldScalarBaseMult1024 failure: ((|255| * basepoint) * basepoint)... 1024 did not match",
		)
	}
}

func TestBasepointMolestation(t *testing.T) {
	defer leak.VerifyNone(t)
	var err error = fmt.Errorf("err never returned")
	oBasepoint := goc25519sm.Basepoint
	err = goc25519sm.OldScalarVerifyBasepoint(goc25519sm.Basepoint)
	if err != nil {
		t.Fatal(
			fmt.Sprintf(
				"goc25519sm.TestBasepointMolestation.OldScalarVerifyBasepoint failure: falsely detected molestation of pristine Basepoint: got %v, wanted %v",
				err,
				goc25519sm.Basepoint,
			),
		)
	} else {
		err = nil
	}
	goc25519sm.Basepoint = [goc25519sm.X25519Size]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
		0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24,
		0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32,
	}
	err = goc25519sm.OldScalarVerifyBasepoint(goc25519sm.Basepoint)
	if err == nil {
		t.Fatal(
			fmt.Sprintf(
				"goc25519sm.TestBasepointMolestation.OldScalarVerifyBasepoint failure: failed to detect Basepoint molestation: got %v, wanted %v",
				goc25519sm.Basepoint,
				oBasepoint,
			),
		)
	}
	goc25519sm.Basepoint = oBasepoint
}

func TestOldScalarBaseMult200(t *testing.T) {
	defer leak.VerifyNone(t)
	var err error = fmt.Errorf("err never returned")
	var a, b [goc25519sm.X25519Size]byte
	in := &a
	out := &b
	a[0] = 1
	for i := 0; i < 200; i++ {
		err = goc25519sm.OldScalarBaseMult(out, in)
		if err != nil {
			t.Fatal(
				fmt.Sprintf("goc25519sm.TestOldScalarBaseMult200.OldScalarBaseMult failure: %v",
					err,
				),
			)
		}
		in, out = out, in
	}
	result := fmt.Sprintf("%x", in[:])
	if result != expectedHex {
		t.Errorf(
			"goc25519sm.TestOldScalarBaseMult200 failure: incorrect result: got %s, want %s",
			result,
			expectedHex,
		)
	}
}

func TestLowOrderPoints(t *testing.T) {
	defer leak.VerifyNone(t)
	var x [goc25519sm.X25519Size]byte
	var err error = fmt.Errorf("err never returned")
	scalar := make([]byte, goc25519sm.X25519Size)
	tscalar := scalar
	copy(x[:], tscalar)
	if _, err = crand.Read(tscalar); err != nil {
		t.Fatal(
			fmt.Sprintf(
				"goc25519sm.TestLowOrderPoints failure: crand.Read failure: %v",
				err,
			),
		)
	} else {
		err = nil
	}
	for i, p := range lowOrderPoints {
		var out [goc25519sm.X25519Size]byte
		err = goc25519sm.OldScalarMult(&out, &x, &p)
		if err == nil {
			t.Errorf(
				"goc25519sm.TestLowOrderPoints.OldScalarMult failure: %d: expected error, got nil",
				i,
			)
		}
		var allZeroOutput [goc25519sm.X25519Size]byte
		if out != allZeroOutput {
			t.Errorf(
				"goc25519sm.TestLowOrderPoints.OldScalarMult failure: %d: expected all zero output, got %x",
				i,
				out,
			)
		}
	}
}
