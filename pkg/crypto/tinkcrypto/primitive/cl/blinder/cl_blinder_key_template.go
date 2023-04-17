//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package blinder

import (
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/blinder"
)

// MasterSecretKeyTemplate is for creating CL Master Secret key template.
func MasterSecretKeyTemplate() *tinkpb.KeyTemplate {
	return blinder.MasterSecretKeyTemplate()
}
