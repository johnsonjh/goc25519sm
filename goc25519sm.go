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
// These functions, named 'OldScalarBaseMult' and 'OldScalarMult', provide
// for additional error checking with input and output validation, intended
// to provide equivalence and full compatibility with the implementation
// found in libsodium. These functions implement an API which is compatible
// with the original Go "x/crypto/curve25519" functions, but with the
// addition of returning errors, and are intended to provide an alternative
// to the X25519 function, future-proofed against possible changes to X25519.
// The goal is a "safer" library for certain specific classes of software,
// such as distributed consensus systems, which may be sensitive to behavior
// changes.
//
// While these functions provide an API that is mostly backwards-compatible
// with the original ScalarMult and ScalarBaseMult, the added validation
// checks introduce the possibility that unchecked errors may result in
// additional and unintended cases of apparent zero or null output when
// processing malformed inputs, when compared to the original functions.
// However, these extra checks provide parity with the libsodium
// implementation. For this reason, it is very important that the return
// value is always checked for errors by the caller.
//
// While not specific to this implementation, it should also be noted that
// users must be aware of the implications of copying into fixed size arrays,
// such as the possibility of truncation via unintended short copies, and
// must ensure the correctness of any code which makes use of these
// functions.
//
// Users of this library should familiar with the nuances of working with
// Curve25519. Please review RFC-7748, RFC-8422, and
// https://cr.yp.to/ecdh.html.
//
// For further details. It must also be acknowledged that verification and
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
// library "drop-in compatible" with the original, at least in regards to
// weak key generation. The trade-off is that any unchecked errors, or errors
// in implementation, such as the passing of truncated scalar or point
// inputs, or providing low-order inputs to these functions, results in
// changing possible "silent" security issues (depending on the protocol
// implementation), into application crashes. While it is debatable if
// crashing is actually worse than continuing with possible security
// vulnerabilities, a panic-by-default behavior would at least ensure that
// these errors do not slip by undetected.
// STATUS: In-progress.

// TODO(jhj): (2) OldScalarMult and OldScalarBaseMult should be constrained
// to strictly operate in constant time, even in the case of validation
// failures. This could be achieved by requiring oldScalarMultVerify, which
// already does constant time validation, to always perform all possible
// checks before returning, which may protect against certain types of
// implementation errors.
// STATUS: In-progress.

// TODO(jhj): (3) Validation checks are performed several times, much of
// which could be avoided with the use of https://github.com/awnumar/memguard
// to add mitigations in areas of concern. Most of these mitigations are
// inspired by those which are currently implemented in libsodium.
// STATUS: In-progress.

import (
	csubtle "crypto/subtle"
	"fmt"

	goc25519smLegal "go4.org/legal"
)

const (
	// X25519Size is the fixed (32-bytes, 256-bit) size of the
	// 'scalar', 'point', 'base', and the size of the output, 'dst'.
	X25519Size = 32
)

// CorruptBasepointTest ...
var CorruptBasepointTest bool

// OldScalarMult sets 'dst' to the product ('scalar' * 'point'),
// returning an error in the case of validation failures.
func OldScalarMult(
	dst,
	scalar,
	point *[X25519Size]byte,
) error {
	err := oldScalarMult(
		dst,
		scalar,
		point,
	)
	if err != nil {
		return fmt.Errorf(
			"\ngoc25519sm.OldScalarMult.oldScalarMult FAILURE:\n	dst=%v\n	scalar=%v\n	point=%v\n	%v",
			*dst,
			*scalar,
			*point,
			err,
		)
	}
	_ = oldScalarMultVerify(
		dst,
		scalar,
		point,
	)
	/*	if err != nil {
		return fmt.Errorf(
			"\ngoc25519sm.OldScalarMult.oldScalarMultVerify FAILURE:\n	dst=%v\n	scalar=%v\n	point=%v\n	%v",
			*dst,
			*scalar,
			*point,
			err,
		)
	} */ // Indented for future use
	return nil
}

// OldScalarBaseMult sets 'dst' to the product of ('scalar' * 'base'),
// where base is the canonical Curve25519 generator, returning an
// error in the case of validation failures.
func OldScalarBaseMult(
	dst,
	scalar *[X25519Size]byte,
) error {
	_ = OldScalarMult(
		dst,
		scalar,
		&Basepoint,
	)
	/*	if err != nil {
		return fmt.Errorf(
			"\ngoc25519sm.OldScalarMult FAILURE:\n	dst=%v\n	scalar=%v\n	point=%v\n	%v",
			*dst,
			*scalar,
			Basepoint,
			err,
		)
	} */ // Intended for future use
	return nil
}

// oldScalarMultVerify performs validation of the inputs and outputs
// of the OldScalarMult and OldScalarBaseMult functions.
func oldScalarMultVerify(
	dst,
	scalar,
	point *[X25519Size]byte,
) error {
	// Check for blocklisted point or scalar
	if checkBlocklist(*scalar) || checkBlocklist(*point) {
		return fmt.Errorf(
			"\ngoc25519sm.oldScalarMultVerify.checkBlocklist FAILURE:\n	scalar=%v\n	point=%v",
			*scalar,
			*point,
		)
	}
	// Check for Basepoint molestation when using the standard
	// canonical Curve25519 generator, determined via a constant
	// time check with mitigations against compiler optimizations
	ctPoint := point[:]
	ctBasepoint := Basepoint[:]
	/* var err error */ // Intended for future use
	if csubtle.ConstantTimeCompare(
		ctPoint,
		ctBasepoint,
	) == 1 {
		_ = OldScalarVerifyBasepoint(
			*point,
		)
		/*	if err != nil {
			return fmt.Errorf(
				"\ngoc25519sm.oldScalarMultVerify.OldScalarVerifyBasepoint FAILURE:\n	point=%v\n	%v",
				&point,
				err,
			)
		} */ // Intended for future use
	} else {
		_ = OldScalarVerifyBasepoint(
			Basepoint,
		)
		/*	if err != nil {
			return fmt.Errorf(
				"\ngoc25519sm.oldScalarMultVerify.OldScalarVerifyBasepoint FAILURE:\n	point=%v\n	%v",
				Basepoint,
				err,
			)
		} */ // Intended for future use
	}
	// Detect low-order inputs by checking output
	// See RFC-8422 Sec 5.11 for more information
	var allZeroOutput [X25519Size]byte
	ctDst := dst[:]
	if csubtle.ConstantTimeCompare(
		allZeroOutput[:],
		ctDst,
	) == 1 {
		return fmt.Errorf(
			"\ngoc25519sm.oldScalarMultVerify FAILURE:\n	low-order inputs inferred from output\n		dst=%v",
			*dst,
		)
	}
	return nil
}

// OldScalarVerifyBasepoint verifies that the global Basepoint, which
// defines the standard canonical Curve25519 generator, has not been
// molested. It is automatically called as part of the validation checks,
// but has been exported as it might be useful to others.
func OldScalarVerifyBasepoint(
	Basepoint [X25519Size]byte,
) error {
	ctxBasepoint := Basepoint[:]
	if csubtle.ConstantTimeCompare(ctxBasepoint, []byte{
		0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	},
	) != 1 {
		return fmt.Errorf(
			"\ngoc25519sm.OldScalarVerifyBasepoint FAILURE:\n	ctxBasepoint=%v",
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

// See https://eprint.iacr.org/2017/806.pdf
var blocklist = [][X25519Size]byte{
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

	{
		205, 235, 122, 124, 59, 65, 184, 174,
		22, 86, 227, 250, 241, 159, 196, 106,
		218, 9, 141, 235, 156, 50, 177, 253,
		134, 98, 5, 22, 95, 73, 184, 128,
	},

	{
		76, 156, 149, 188, 163, 80, 140, 36,
		177, 208, 177, 85, 156, 131, 239, 91,
		4, 68, 92, 196, 88, 28, 142, 134,
		216, 34, 78, 221, 208, 159, 17, 215,
	},

	{
		217, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
	},

	{
		218, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
	},

	{
		219, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
	},
}

// checkBlocklist verifies input is not blocklisted
func checkBlocklist(
	input [X25519Size]byte,
) bool {
	isBlocklisted := false
	for _, blockList := range blocklist {
		if csubtle.ConstantTimeCompare(
			input[:],
			blockList[:],
		) == 1 {
			isBlocklisted = true
			break
		}
	}
	return isBlocklisted
}

// init initializes the goc25519sm package
func init() {
	// Register licensing
	goc25519smLegal.RegisterLicense(
		"\nCopyright 2020 Jeffrey H. Johnson.\nCopyright 2020 Gridfinity, LLC.\nCopyright 2020 Frank Denis <j at pureftpd dot org>.\nCopyright 2020 Filippo Valsorda.\nCopyright 2019 The Go Authors.\nCopyright 2015 Google, Inc.\nCopyright 2011 The OpenSSL Project.\nCopyright 1998 Eric Young (eay@cryptsoft.com).\n\nThis product includes software developed by the OpenSSL Project\nfor use in the OpenSSL Toolkit (http://www.openssl.org/).\n\nAll rights reserved.\n\nRedistribution and use in source and binary forms, with or without\nmodification, are permitted provided that the following conditions are\nmet:\n\n   * Redistributions of source code must retain the above copyright\nnotice, this list of conditions and the following disclaimer.\n\n   * Redistributions in binary form must reproduce the above\ncopyright notice, this list of conditions and the following disclaimer\nin the documentation and/or other materials provided with the\ndistribution.\n\n   * Neither the name of Google, Inc. nor the names of its\ncontributors may be used to endorse or promote products derived from\nthis software without specific prior written permission.\n\nTHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS\n'AS IS' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT\nLIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR\nA PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT\nOWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,\nSPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT\nLIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\nDATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\nTHEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE\nOF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n",
	)
}
