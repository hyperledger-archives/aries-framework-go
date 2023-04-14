//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package blinder

import (
	"fmt"

	"github.com/google/tink/go/core/registry"
)

// TODO - find a better way to setup tink than init.
// nolint: gochecknoinits
func init() {
	// TODO - avoid the tink registry singleton.
	err := registry.RegisterKeyManager(newCLBlinderKeyManager())
	if err != nil {
		panic(fmt.Sprintf("prover.init() failed: %v", err))
	}
}
