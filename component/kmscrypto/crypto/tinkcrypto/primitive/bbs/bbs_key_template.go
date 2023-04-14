/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"github.com/golang/protobuf/proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	bbspb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/bbs_go_proto"
)

// BLS12381G2KeyTemplate creates a Tink key template for BBS+ on BLS12-381 curve with G2 group.
func BLS12381G2KeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(bbspb.BBSCurveType_BLS12_381, bbspb.GroupField_G2, commonpb.HashType_SHA256)
}

// createKeyTemplate for BBS+ keys.
func createKeyTemplate(curve bbspb.BBSCurveType, group bbspb.GroupField, hash commonpb.HashType) *tinkpb.KeyTemplate {
	format := &bbspb.BBSKeyFormat{
		Params: &bbspb.BBSParams{
			HashType: hash,
			Curve:    curve,
			Group:    group,
		},
	}

	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		panic("failed to marshal BBSKeyFormat proto")
	}

	return &tinkpb.KeyTemplate{
		TypeUrl:          bbsSignerKeyTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}
