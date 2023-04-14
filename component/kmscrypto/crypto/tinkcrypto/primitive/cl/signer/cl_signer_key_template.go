//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"

	clpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/cl_go_proto"
)

// CredDefKeyTemplate si fro creating CL Cred Def key template.
func CredDefKeyTemplate(attrs []string) *tinkpb.KeyTemplate {
	format := &clpb.CLCredDefKeyFormat{
		Params: &clpb.CLCredDefParams{
			Attrs: attrs,
		},
	}

	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		panic("failed to marshal CLKeyFormat proto")
	}

	return &tinkpb.KeyTemplate{
		TypeUrl:          clSignerKeyTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}
