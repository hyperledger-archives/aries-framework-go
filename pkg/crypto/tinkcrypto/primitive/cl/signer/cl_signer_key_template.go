//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/signer"
)

// CredDefKeyTemplate is for creating CL Cred Def key template.
func CredDefKeyTemplate(attrs []string) *tinkpb.KeyTemplate {
	return signer.CredDefKeyTemplate(attrs)
}
