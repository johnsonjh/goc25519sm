// Copyright 2020 Jeffrey H. Johnson.
// Copyright 2020 Gridfinity, LLC.
// Copyright 2019 The Go Authors.
// All rights reserved.
// Use of this source code is governed by the BSD-style
// license that can be found in the LICENSE file.

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
