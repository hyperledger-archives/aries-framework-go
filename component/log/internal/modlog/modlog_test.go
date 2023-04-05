/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modlog

import (
	"testing"
)

func TestModLog(t *testing.T) {
	const module = "sample-module"
	modLogger := NewModLog(GetSampleCustomLogger(module), module)
	VerifyCustomLogger(t, modLogger, module)
}
