// Copyright 2020 Jeffrey H. Johnson.
// Copyright 2020 Gridfinity, LLC.
// Copyright 2019 The Go Authors.
// All rights reserved.
// Use of this source code is governed by the BSD-style
// license that can be found in the LICENSE file.

// Package goc25519sm provides an implementation of scalar multiplication on
// the elliptic curve known as Curve25519.
//
// This library provides functions mostly backwards-compatible with the
// implementations of 'ScalarBaseMult' and 'ScalarMult' provided in Google's
// "x/crypto/curve25519" library.
//
// These functions, named 'OldScalarBaseMult' and 'OldScalarMult', provide for
// additional error checking with input and output validation, intended to
// provide equivalence and full compatibility with the implementation found
// in libsodium. These functions implement an API which is compatible with the
// original Go "x/crypto/curve25519" functions, but with the addition of
// returning errors, and are intended to provide an alternative to the X25519
// function, future-proofed against possible changes to X25519. The goal is
// a "safer" library for certain specific classes of software, such as
// distributed consensus systems, which may be sensitive to behavior changes.
//
// While these functions provide an API that is mostly backwards-compatible
// with the original ScalarMult and ScalarBaseMult, the added validation checks
// introduce the possibility that unchecked errors may result in additional and
// unintended cases of apparent zero or null output when processing malformed
// inputs, when compared to the original functions. However, these extra checks
// provide parity with the libsodium implementation. For this reason, it is very
// important that the return value is always checked for errors by the caller.
//
// While not specific to this implementation, it should also be noted that
// users must be aware of the implications of copying into fixed size arrays,
// such as the possibility of truncation via unintended short copies, and must
// ensure the correctness of any code which makes use of these functions.
//
// Users of this library should familiar with the nuances of working with
// Curve25519. Please review RFC-7748, RFC-8422, and https://cr.yp.to/ecdh.html
// for further details. It must also be acknowledged that verification and
// validation checks, as performed by this and other libraries, such as
// libsodium, are extremely controversial. For background, please review
// https://research.kudelskisecurity.com/2017/04/25/should-ecdh-keys-be-validated/,
// https://moderncrypto.org/mail-archive/curves/2017/000896.html,
// https://vnhacker.blogspot.com/2016/08/the-internet-of-broken-protocols.html,
// https://vnhacker.blogspot.com/2015/09/why-not-validating-curve25519-public.html,
// and https://moderncrypto.org/mail-archive/noise/2017/000971.html.
package goc25519sm

// TODO(jhj): (1) An possible enhancement which could avoid any possible
// ramifications of callers not checking for error conditions would be to
// panic by default, rather than returning any error. Users could change the
// behavior from panic to errors by taking some explicit action, such as
// calling a function for this specific purpose. While this could make this
// library "drop-in compatible" with the original, at least in regards to weak
// key generation, the trade-off is that any unchecked errors, or errors in
// implementation, such as the passing truncated scalar or point inputs, or
// providing low-order inputs to these functions results in changing possible
// "silent" security issues (depending on the protocol implementation), into
// application crashes. While it is debatable if crashing is actually worse
// than continuing with possible security vulnerabilities, a panic-by-default
// behavior would at least ensure that these errors do not slip by undetected.

// TODO(jhj): (2) OldScalarMult and OldScalarBaseMult, should be constrained to
// strictly operate in constant time, even in the case of validation failures.
// This could be achieved by requiring oldScalarMultVerify, which already does
// constant time validation, to always perform all possible checks before
// returning, which may protect against certain types of implementation errors.

// TODO(jhj): (3) Validation checks are performed several times, much of which
// could be avoided with the use of https://github.com/awnumar/memguard, which
// implements mitigations in areas of concern. Most of these mitigations are
// inspired by those which are currently implemented in libsodium.

import (
	csubtle "crypto/subtle"
	"fmt"
)

const (
	// X25519Size is the fixed (32-byte, 256-bit) size of
	// 'scalar', 'point', 'base', and the size of the output, 'dst'.
	X25519Size = 32
)

// OldScalarMult sets 'dst' to the product ('scalar' * 'point'),
// returning an error in the case of validation failures.
func OldScalarMult(dst, scalar, point *[X25519Size]byte) error {
	var err error
	err = oldScalarMult(dst, scalar, point)
	if err != nil {
		return fmt.Errorf("goc25519sm.OldScalarMult.oldScalarMult failure: %v", err)
	}
	err = oldScalarMultVerify(dst, scalar, point)
	if err != nil {
		return fmt.Errorf("goc25519sm.OldScalarMult.oldScalarMultVerify failure: %v", err)
	}
	return nil
}

// OldScalarBaseMult sets 'dst' to the product of ('scalar' * 'base'),
// where base is the canonical Curve25519 generator, returning an
// error in the case of validation failures.
func OldScalarBaseMult(dst, scalar *[X25519Size]byte) error {
	var err error
	err = OldScalarMult(dst, scalar, &Basepoint)
	if err != nil {
		return fmt.Errorf("goc25519sm.OldScalarBaseMult failure: %v", err)
	}
	return nil
}

// oldScalarMultVerify performs validation of the inputs and outputs
// of the OldScalarMult and OldScalarBaseMult functions.
func oldScalarMultVerify(dst, scalar, point *[X25519Size]byte) error {
	// Check for bad scalar length input
	if l := len(scalar); l != X25519Size {
		return fmt.Errorf(
			"goc25519sm.oldScalarMultVerify failure: Bad scalar length: %d, expected %d",
			l,
			X25519Size,
		)
	}
	// Check for bad point length input
	if l := len(point); l != X25519Size {
		return fmt.Errorf(
			"goc25519sm.oldScalarMultVerify failure: Bad point length: %d, expected %d",
			l,
			X25519Size,
		)
	}
	// Check for Basepoint molestation when using the standard
	// canonical Curve25519 generator, determined via a constant
	// time check, with mitigations against compiler optimizations.
	ctPoint := point[:]
	ctBasepoint := Basepoint[:]
	var err error
	if csubtle.ConstantTimeCompare(ctPoint, ctBasepoint) == 1 {
		err = OldScalarVerifyBasepoint(*point)
		if err != nil {
			return fmt.Errorf(
				"goc25519sm.oldScalarMultVerify.OldScalarVerifyBasepoint failure: %v",
				err,
			)
		}
	} else {
		cteBasepoint := Basepoint[:]
		_ = csubtle.ConstantTimeCompare(ctPoint, cteBasepoint)
	}
	// Detect for low-order inputs by checking output
	// See RFC-8422 S:5.11 for more information
	var allZeroOutput [X25519Size]byte
	ctDst := dst[:]
	if csubtle.ConstantTimeCompare(allZeroOutput[:], ctDst) == 1 {
		return fmt.Errorf(
			"goc25519sm.oldScalarMultVerify failure: Bad input point: low-order point detected",
		)
	}
	return nil
}

// OldScalarVerifyBasepoint verifies that the global Basepoint, which
// defines the standard canonical Curve25519 generator, has not been molested.
// It is automatically called at the time of package initialization and during
// validation operations, but is exported as it might be useful to others.
func OldScalarVerifyBasepoint(Basepoint [X25519Size]byte) error {
	ctxBasepoint := Basepoint[:]
	if csubtle.ConstantTimeCompare(ctxBasepoint, []byte{
		0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}) != 1 {
		return fmt.Errorf(
			"goc25519sm.OldScalarVerifyBasepoint failure: got %v",
			ctxBasepoint,
		)
	}
	return nil
}

// Basepoint is the x coordinate of
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

// init initializes the goc25519sm package
func init() {
	// Ensure that Basepoint has not been molested
	var initerr error
	initerr = OldScalarVerifyBasepoint(Basepoint)
	if initerr != nil {
		panic(fmt.Sprintf("goc25519sm.init.OldScalarVerifyBasepoint failure: %v", initerr))
	}
}
