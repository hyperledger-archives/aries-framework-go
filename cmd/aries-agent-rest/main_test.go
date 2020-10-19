/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/
package main

import (
	"os"
	"testing"
)

// Correct behaviour is for main to finish with exit code 0.
// This test fails otherwise. However, this can't be checked by the unit test framework. The *testing.T argument is
// only there so that this test gets picked up by the framework but otherwise we don't need it.
func TestWithoutUserAgs(t *testing.T) { //nolint: unparam //see above
	setUpArgs()
	main()
}

// Strips out the extra args that the unit test framework adds.
// This allows main() to execute as if it was called directly from the command line.
func setUpArgs() {
	os.Args = os.Args[:1]
}
