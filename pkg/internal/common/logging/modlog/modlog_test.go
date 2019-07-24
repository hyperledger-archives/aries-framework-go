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
	modLogger := &modLog{logger: GetSampleCustomLogger(&buf, module), module: module}
	VerifyCustomLogger(t, modLogger, module)
}
