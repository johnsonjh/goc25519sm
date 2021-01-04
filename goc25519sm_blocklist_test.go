// Copyright 2021 Jeffrey H. Johnson.
// Copyright 2021 Gridfinity, LLC.
// Copyright 2020 Frank Denis <j at pureftpd dot org>.
// Copyright 2012 The Go Authors.
//
// All rights reserved.
//
// Use of this source code is governed by the BSD-style
// license that can be found in the LICENSE file.

package goc25519sm // import "go.gridfinity.dev/goc25519sm"

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	u "go.gridfinity.dev/leaktestfe"
)

func TestBlocklistPoint(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	var x [X25519Size]byte
	var err error
	point := make(
		[]byte,
		X25519Size,
	)
	tpoint := point
	copy(
		x[:],
		point,
	)
	if _, err = crand.Read(
		tpoint,
	); err != nil {
		t.Fatal(
			fmt.Sprintf(
				"\ngoc25519sm_blocklist_test.TestBlocklist.crand.Read FAILURE:\n   %v",
				err,
			),
		)
	}
	for i, p := range blocklist {
		var out [X25519Size]byte
		err = OldScalarMult(
			&out,
			&x,
			&p,
		)
		if err == nil {
			t.Errorf(
				"\ngoc25519sm_blocklist_test.TestBlocklist.OldScalarMult FAILURE:\n    BLOCKLIST TEST %v FAILED TO DETECT BAD INPUT POINT P\n	out=%v\n	x=%v\n	p=%v\n	%v",
				i,
				out,
				x,
				p,
				err,
			)
		}
	}
}

func TestBlocklistScalar(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	var p [X25519Size]byte
	var err error
	scalar := make(
		[]byte,
		X25519Size,
	)
	tscalar := scalar
	copy(
		p[:],
		tscalar,
	)
	if _, err = crand.Read(
		tscalar,
	); err != nil {
		t.Fatal(
			fmt.Sprintf(
				"\ngoc25519sm_blocklist_test.TestBlocklist.crand.Read FAILURE:\n   %v",
				err,
			),
		)
	}
	for i, x := range blocklist {
		var out [X25519Size]byte
		err = OldScalarMult(
			&out,
			&x,
			&p,
		)
		if err == nil {
			t.Errorf(
				"\ngoc25519sm_blocklist_test.TestBlocklist.OldScalarMult FAILURE:\n    BLOCKLIST TEST %v FAILED TO DETECT BAD INPUT SCALAR X\n	out=%v\n	x=%v\n	p=%v\n	%v",
				i,
				out,
				x,
				p,
				err,
			)
		}
	}
}
