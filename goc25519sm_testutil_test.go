// Copyright 2020 Gridfinity, LLC.
// Copyright 2019 The Go Authors.
// All rights reserved.
// Use of this source code is governed by the BSD-style
// license that can be found in the LICENSE file.

package goc25519sm_test

import (
	"fmt"
	"testing"

	u "go.gridfinity.dev/leaktestfe"
)

func TestLeakplugDisabled(
	t *testing.T,
) {
	err := u.Leakplug(
		t,
	)
	if err != nil {
		t.Fatal(
			fmt.Sprintf(
				"\ngoc25519sm_testutil_test.TestLeakplugDisabled.Leakplug FAILURE:\n	%v",
				err,
			),
		)
	}
}

func TestLeakplugEnabled(
	t *testing.T,
) {
	err := u.Leakplug(
		t,
	)
	if err != nil {
		t.Fatal(
			fmt.Sprintf(
				"\ngoc25519sm_testutil_test.TestLeakplugEnabled.Leakplug FAILURE:\n	%v",
				err,
			),
		)
	}
}
