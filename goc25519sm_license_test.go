// Copyright 2021 Jeffrey H. Johnson <trnsz@pobox.com>.
// Copyright 2021 Gridfinity, LLC.
// Copyright 2012 The Go Authors.
//
// All rights reserved.
//
// Use of this source code is governed by the BSD-style
// license that can be found in the LICENSE file.

package goc25519sm

import (
	"fmt"
	"testing"

	u "github.com/johnsonjh/leaktestfe"
	licn "go4.org/legal"
)

func TestLicense(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	licenses := licn.Licenses()
	if len(
		licenses,
	) == 0 {
		t.Fatal(
			"\ngoc25519sm_license_test.TestLicense.Licenses FAILURE",
		)
	} else {
		t.Log(
			fmt.Sprintf(
				"\n%v\n",
				licenses,
			),
		)
	}
}
