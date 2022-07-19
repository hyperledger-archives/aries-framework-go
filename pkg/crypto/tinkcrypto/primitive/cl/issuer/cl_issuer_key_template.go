//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/


package issuer

import (
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	clpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/cl_go_proto"
	"google.golang.org/protobuf/proto"
)

// CL Cred Def key template.
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
		TypeUrl:          clIssuerKeyTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}
