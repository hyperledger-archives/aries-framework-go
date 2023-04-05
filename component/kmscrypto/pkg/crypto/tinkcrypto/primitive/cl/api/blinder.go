//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

// Blinder is the blinding interface primitive for CL Anoncreds used by Tink.
type Blinder interface {
	Blind(values map[string]interface{}) ([]byte, error)
	Free() error
}
