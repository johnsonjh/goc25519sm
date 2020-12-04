// Copyright 2020 Jeffrey H. Johnson.
// Copyright 2020 Gridfinity, LLC.
// Copyright 2019 The Go Authors.
// All rights reserved.
// Use of this source code is governed by the BSD-style
// license that can be found in the LICENSE file.

// Package goc25519sm provides an implementation of
// scalar multiplication on the elliptic curve known as Curve25519.
// See https://cr.yp.to/ecdh.html and RFC-7748 for additional information.
package goc25519sm_test // import oc25510sm "github.com/johnsonjh/goc25519sm"

import (
	"fmt"

	goc25519sm "github.com/johnsonjh/goc25519sm"
)

// OldScalarMult sets dst to the product in * base, where
// dst and base are the x coordinates of group points, and
// where all values are in little-endian form. Care must be
// taken when copying into fixed-size arrays to avoid bugs!
func ExampleOldScalarMult() {
	var err error
	var dst [goc25519sm.X25519Size]byte
	err = goc25519sm.OldScalarMult(&dst, &goc25519sm.ExamplePointA, &goc25519sm.Basepoint)
	if err != nil {
		fmt.Println(fmt.Errorf("%v", err))
	} else {
		fmt.Println(fmt.Sprintf("%v", dst))
	}
	// Output: [66 122 229 107 218 63 64 231 243 68 229 108 16 57 164 54 219 131 67 199 51 187 152 115 156 62 194 207 141 229 208 116]
}

// OldScalarBaseMult sets dst to the product of scalar * base, where
// dst and base are the x coordinates of group points, base is the
// canonical Curve25519 generator, with all values in little-endian form.
// Care must be taken when copying into fixed-size arrays to avoid bugs!
func ExampleOldScalarBaseMult() {
	var err error
	var dst [goc25519sm.X25519Size]byte
	err = goc25519sm.OldScalarBaseMult(&dst, &goc25519sm.ExamplePointB)
	if err != nil {
		fmt.Println(fmt.Errorf("%v", err))
	} else {
		fmt.Println(fmt.Sprintf("%v", dst))
	}
	// Output: [93 146 199 126 178 229 251 64 79 89 30 113 124 116 224 71 248 157 194 158 254 59 217 255 200 96 218 131 168 125 174 103]
}
