/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secp256k1

import (
	"github.com/golang/protobuf/proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	secp256k1pb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto"
)

// This file contains pre-generated KeyTemplates for Signer and Verifier.
// One can use these templates to generate new Keysets.

// DERKeyTemplate is a KeyTemplate that generates a new ECDSA secp256k1 private key with the following parameters:
//   - Hash function: SHA256
//   - Curve: secp256k1
//   - Signature encoding: DER
//   - Output prefix type: TINK
func DERKeyTemplate() (*tinkpb.KeyTemplate, error) {
	return createECDSAKeyTemplate(commonpb.HashType_SHA256,
		secp256k1pb.BitcoinCurveType_SECP256K1,
		secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER,
		tinkpb.OutputPrefixType_TINK)
}

// IEEEP1363KeyTemplate is a KeyTemplate that generates a new ECDSA secp256k1 private key with the following parameters:
//   - Hash function: SHA256
//   - Curve: secp256k1
//   - Signature encoding: IEEE-P1363
//   - Output prefix type: TINK
func IEEEP1363KeyTemplate() (*tinkpb.KeyTemplate, error) {
	return createECDSAKeyTemplate(commonpb.HashType_SHA256,
		secp256k1pb.BitcoinCurveType_SECP256K1,
		secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_IEEE_P1363,
		tinkpb.OutputPrefixType_TINK)
}

// createECDSAKeyTemplate creates a KeyTemplate containing a Secp256K1KeyFormat with the given parameters.
func createECDSAKeyTemplate(hashType commonpb.HashType, curve secp256k1pb.BitcoinCurveType,
	encoding secp256k1pb.Secp256K1SignatureEncoding, prefixType tinkpb.OutputPrefixType) (*tinkpb.KeyTemplate, error) {
	params := &secp256k1pb.Secp256K1Params{
		HashType: hashType,
		Curve:    curve,
		Encoding: encoding,
	}
	format := &secp256k1pb.Secp256K1KeyFormat{Params: params}

	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		return nil, err
	}

	return &tinkpb.KeyTemplate{
		TypeUrl:          secp256k1SignerTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: prefixType,
	}, nil
}
