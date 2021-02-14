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
	"fmt"
	"os"
	"testing"

	u "go.gridfinity.dev/leaktestfe"
)

func TestMain(m *testing.M) {
	CorruptBasepointTest = true
	exitVal := m.Run()
	os.Exit(
		exitVal,
	)
}

func TestOldScalarMultVerifyFailure(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	var dst, scalar, point [X25519Size]byte
	copy(dst[:], ExamplePointB[:])
	copy(scalar[:], ExamplePointA[:])
	copy(point[:], ExamplePointB[:])
	err := oldScalarMultVerify(&dst, &scalar, &point)
	if err != nil {
		t.Fatal(
			fmt.Sprintf(
				"\ngoc25519sm_verify_test.TestOldScalarMultVerifyFailure.oldScalarMultVerify FAILURE:\n	dst=%v\n	scalar=%v\n	point=%v\n	%v",
				dst,
				scalar,
				point,
				err,
			),
		)
	}
}

func TestOldScalarMultVerifyLowFailure(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	var dst, scalar, point [X25519Size]byte
	copy(scalar[:], ExamplePointA[:])
	copy(point[:], ExamplePointB[:])
	err := oldScalarMultVerify(&dst, &scalar, &point)
	if err == nil {
		t.Fatal(
			fmt.Sprintf(
				"\ngoc25519sm_verify_test.TestOldScalarMultVerifyLowFailure.oldScalarMultVerify FAILURE:\n	dst=%v\n	scalar=%v\n	point=%v\n	%v",
				dst,
				scalar,
				point,
				err,
			),
		)
	}
}

func TestInitCorruptBasepointTestFailure(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	if !CorruptBasepointTest {
		t.Fatal(
			"\ngoc25519sm_verify_test.TestInitFailure FAILURE:\n	CorruptBasepointTest unset",
		)
	}
}
