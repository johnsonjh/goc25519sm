// Copyright 2020 Gridfinity, LLC.
// Copyright 2019 The Go Authors.
// All rights reserved.
// Use of this source code is governed by the BSD-style
// license that can be found in the LICENSE file.

package testutil_test

import (
	"testing"
	"fmt"

	u "github.com/johnsonjh/goc25519sm/testutil"
)

func TestLeakVerifyNoneDisabled(
	t *testing.T,
) {
	err := u.LeakVerifyNone(
		t,
	)
	if err != nil {
		t.Fatal(
			fmt.Sprintf(
				"\ngoc25519sm_testutil_test.TestLeakVerifyNoneDisabled.LeakVerifyNone FAILURE:\n	%v",
				err,
			),
		)
	}
}

func TestLeakVerifyNoneEnabled(
	t *testing.T,
) {
	err := u.LeakVerifyNone(
		t,
	)
	if err != nil {
		t.Fatal(
			fmt.Sprintf(
				"\ngoc25519sm_testutil_test.TestLeakVerifyNoneEnabled.LeakVerifyNone FAILURE:\n	%v",
				err,
			),
		)
	}
}

