// Copyright 2021 Jeffrey H. Johnson <trnsz@pobox.com>
// Copyright 2021 Gridfinity, LLC.
// Copyright 2019 The Go Authors.
//
// All rights reserved.
//
// Use of this source code is governed by the BSD-style
// license that can be found in the LICENSE file.

package goc25519sm_test

import (
	"testing"

	u "github.com/johnsonjh/leaktestfe"
)

func TestLeakplugDisabled(
	t *testing.T,
) {
	u.Leakplug(
		t,
	)
}

func TestLeakplugEnabled(
	t *testing.T,
) {
	u.Leakplug(
		t,
	)
}
