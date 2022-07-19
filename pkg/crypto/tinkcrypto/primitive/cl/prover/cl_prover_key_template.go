//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package prover

import (
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	clpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/cl_go_proto"
	"google.golang.org/protobuf/proto"
)

// CL Master Secret key template.
func MasterSecretKeyTemplate() *tinkpb.KeyTemplate {
	format := &clpb.CLMasterSecretKeyFormat{}

	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		panic("failed to marshal CLMasterSecret proto")
	}

	return &tinkpb.KeyTemplate{
		TypeUrl:          clProverKeyTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}
