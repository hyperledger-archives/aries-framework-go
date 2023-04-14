/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package aead provides implementations of the AEAD primitive.
//
// AEAD encryption assures the confidentiality and authenticity of the data. This primitive is CPA secure.
package aead

import (
	// import to initialize.
	_ "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead"
)
