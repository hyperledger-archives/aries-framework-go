//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package blinder

import (
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"

	clpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/cl_go_proto"
)

// MasterSecretKeyTemplate is for creating CL Master Secret key template.
func MasterSecretKeyTemplate() *tinkpb.KeyTemplate {
	format := &clpb.CLMasterSecretKeyFormat{}

	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		panic("failed to marshal CLMasterSecret proto")
	}

	return &tinkpb.KeyTemplate{
		TypeUrl:          clBlinderKeyTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}
