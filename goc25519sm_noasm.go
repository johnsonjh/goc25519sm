// Copyright 2021 Jeffrey H. Johnson <trnsz@pobox.com>.
// Copyright 2021 Gridfinity, LLC.
// Copyright 2020 The Go Authors.
//
// All rights reserved.
//
// Use of this source code is governed by the BSD-style
// license that can be found in the LICENSE file.

//go:build !amd64 || !gc || purego
// +build !amd64 !gc purego

package goc25519sm

import (
	"fmt"
)

// OldScalarMult -> noasm
func oldScalarMult(
	dst,
	scalar,
	base *[X25519Size]byte,
) error {
	var err error
	OldScalarMultGeneric(
		dst,
		scalar,
		base,
	)
	/*	if err != nil {
		return fmt.Errorf(
			"\ngoc25519sm.oldScalarMult.OldScalarMultGeneric FAILURE:\n	dst=%v\n	scalar=%v\n	base=%v\n	%v",
			dst,
			scalar,
			base,
			err,
		)
	} */ // Intended for future use
	err = oldScalarMultVerify(
		dst,
		scalar,
		base,
	)
	if err != nil {
		return fmt.Errorf(
			"\ngoc25519sm.oldScalarMult.OldScalarMultGeneric.oldScalarMultVerify FAILURE:\n	dst=%v\n	scalar=%v\n	base=%v\n	%v",
			*dst,
			*scalar,
			*base,
			err,
		)
	}
	return nil
}
