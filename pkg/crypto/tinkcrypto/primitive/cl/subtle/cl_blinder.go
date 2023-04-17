//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/subtle"
)

// CLBlinder is used for blinding CL MasterSecret with arbitrary values.
type CLBlinder = subtle.CLBlinder

// NewCLBlinder creates a new instance of CL Blinder with the provided privateKey.
func NewCLBlinder(key []byte) (*CLBlinder, error) {
	return subtle.NewCLBlinder(key)
}
