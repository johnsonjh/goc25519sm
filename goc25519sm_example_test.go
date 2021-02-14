// Copyright 2021 Gridfinity, LLC.
// Copyright 2019 The Go Authors.
//
// All rights reserved.
//
// Use of this source code is governed by the BSD-style
// license that can be found in the LICENSE file.

// Package goc25519sm_test provides tests for the goc25519sm library.
package goc25519sm_test

import (
	"fmt"

	goc25519sm "go.gridfinity.dev/goc25519sm"
)

// OldScalarMult sets 'dst' to the product of ('scalar' * 'point'), where
// 'scalar' and 'point' are the x coordinates of group points, with all values
// specified in little-endian form. As always, care must be taken when
// copying 'dst' into a fixed-size array to avoid potential application bugs.
func ExampleOldScalarMult() {
	var err error
	var dst [goc25519sm.X25519Size]byte
	err = goc25519sm.OldScalarMult(
		&dst,
		&goc25519sm.ExamplePointA,
		&goc25519sm.Basepoint,
	)
	if err != nil {
		fmt.Println(
			fmt.Errorf(
				"\ngoc25519sm_test.ExampleOldScalarMult.goc25519sm.OldScalarMult FAILURE:\n	dst=%v\n	point=%v\n	base=%v\n	%v",
				dst,
				goc25519sm.ExamplePointA,
				goc25519sm.Basepoint,
				err,
			),
		)
	} else {
		fmt.Printf(
			"%v",
			dst,
		)
	}
	// Output: [66 122 229 107 218 63 64 231 243 68 229 108 16 57 164 54 219 131 67 199 51 187 152 115 156 62 194 207 141 229 208 116]
}

// OldScalarBaseMult sets 'dst' to the product of ('scalar' * 'base'), where
// 'scalar' and 'base' are the x coordinates of group points, and 'base' is
// always the standard canonical Curve25519 generator, with all values
// specified in little-endian form. As always, care must be taken by when
// copying 'dst' into a fixed-size array to avoid potential application bugs.
func ExampleOldScalarBaseMult() {
	var err error
	var dst [goc25519sm.X25519Size]byte
	err = goc25519sm.OldScalarBaseMult(
		&dst,
		&goc25519sm.ExamplePointB,
	)
	if err != nil {
		fmt.Println(
			fmt.Errorf(
				"\ngoc25519sm_test.ExampleOldScalarBaseMult.goc25519sm.OldScalarBaseMult FAILURE:\n	dst=%v\n	point=%v\n	%v",
				dst,
				goc25519sm.ExamplePointB,
				err,
			),
		)
	} else {
		fmt.Printf(
			"%v\n",
			dst,
		)
	}
	// Output: [93 146 199 126 178 229 251 64 79 89 30 113 124 116 224 71 248 157 194 158 254 59 217 255 200 96 218 131 168 125 174 103]
}
