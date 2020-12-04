// Copyright 2020 Jeffrey H. Johnson.
// Copyright 2020 Gridfinity, LLC.
// Copyright 2019 The Go Authors.
// All rights reserved.
// Use of this source code is governed by the BSD-style
// license that can be found in the LICENSE file.

// Package OldCurve25518ScalarMult contains a non-deprecated, mostly
// backwards-compatible implemention of ScalarBaseMult and ScalarMult
// (as OldScalarBaseMult and ScalarMult), with validation and error
// checking, provided as an alternative to the Go X2559 function.
package OldCurve25519ScalarMult

import (
	csubtle "crypto/subtle"
	"fmt"
)

const (
	// X25519Size is the size of the scalar and point inputs,
	// as well as the size of the expected output, in bytes.
	X25519Size = 32
)

// OldScalarMult sets dst to the product scalar * point.
func OldScalarMult(dst, scalar, point *[X25519Size]byte) error {
	oldScalarMult(dst, scalar, point)
	err := oldScalarMultVerify(dst, scalar, point)
	if err != nil {
		return fmt.Errorf("OldCurve25519ScalarMult.OldScalarMult: %v", err)
	}
	return nil
}

// OldScalarBaseMult sets dst to the product of scalar * base,
// where base is the canonical Curve25519 generator.
func OldScalarBaseMult(dst, scalar *[X25519Size]byte) error {
	err := OldScalarMult(dst, scalar, &Basepoint)
	if err != nil {
		return fmt.Errorf("OldCurve25519ScalarMult.OldScalarBaseMult: %v", err)
	}
	return nil
}

// oldScalarMultVerify performs validation of the input and output
func oldScalarMultVerify(
	dst *[X25519Size]byte,
	scalar *[X25519Size]byte,
	point *[X25519Size]byte,
) error {
	// Check for bad scalar length input
	if l := len(scalar); l != X25519Size {
		return fmt.Errorf(
			"OldCurve25519ScalarMult.oldScalarMultVerify: Bad scalar length: %d, expected %d",
			l,
			X25519Size,
		)
	}
	// Check for bad point length input
	if l := len(point); l != X25519Size {
		return fmt.Errorf(
			"OldCurve25519ScalarMult.oldScalarMultVerify: Bad point length: %d, expected %d",
			l,
			X25519Size,
		)
	}
	// Check for Basepoint molestation
	if &point[0] == &Basepoint[0] {
		oldScalarVerifyBasepoint(Basepoint)
	}
	// Detect for low-order inputs by checking output
	// See RFC-8422 S:5.11 for more information
	var allZeroOutput [X25519Size]byte
	if csubtle.ConstantTimeCompare(allZeroOutput[:], dst[:]) == 1 {
		return fmt.Errorf(
			"OldCurve25519ScalarMult.oldScalarMultVerify: Bad input point: low-order point detected",
		)
	}
	return nil
}

// oldScalarVerifyBasepoint verifies that Basepoint has not been molested
func oldScalarVerifyBasepoint(Basepoint [X25519Size]byte) error {
	sBasepoint := Basepoint[:]
	if csubtle.ConstantTimeCompare(sBasepoint, []byte{
		0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}) != 1 {
		return fmt.Errorf(
			"OldCurve25519ScalarMult.oldScalarVerifyBasepoint failure: got %v",
			sBasepoint,
		)
	}
	return nil
}

// Basepoint is the x corrdinate of
// the canonical Curve25519 generator.
var (
	Basepoint = [X25519Size]byte{
		9, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	}
)

// ExamplePointA is the x coordinate of
// another generator of the curve.
var (
	ExamplePointA = [X25519Size]byte{
		56, 111, 58, 113, 60, 115, 62, 117,
		64, 119, 66, 121, 68, 123, 70, 125,
		72, 127, 74, 129, 76, 131, 78, 133,
		80, 135, 82, 137, 84, 139, 86, 141,
	}
)

// ExamplePointB is the x coordinate of
// yet another generator of the curve.
var (
	ExamplePointB = [X25519Size]byte{
		11, 111, 87, 253, 31, 118, 19, 183,
		31, 191, 89, 100, 10, 209, 21, 101,
		88, 104, 18, 108, 17, 223, 38, 133,
		99, 199, 99, 127, 16, 204, 64, 130,
	}
)

// init initializes the OldCurve25519ScalarMult package
func init() {
	// Ensure that Basepoint has not been molested
	err := oldScalarVerifyBasepoint(Basepoint)
	if err != nil {
		panic(fmt.Sprintf("OldCurve25519ScalarMult.init failure: %v", err))
	}
}
