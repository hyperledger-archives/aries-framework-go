/*
Licensed under the Apache License, Version 2.0 (the "License");

you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package hybriddh

import (
	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	commonpb "github.com/google/tink/proto/common_go_proto"
	eciespb "github.com/google/tink/proto/ecies_aead_hkdf_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// This file contains pre-generated KeyTemplates for HybridEncrypt keys. One can use these templates
// to generate new Keysets.

// ECDHESAES128GCMKeyTemplate is a KeyTemplate that generates an ECDH P-256 and decapsulation key AES128-GCM key with
// the following parameters:
//  - KEM: ECDH over NIST P-256
//  - DEM: AES128-GCM
//  - KDF: HKDF-HMAC-SHA256 with an empty salt
func ECDHESAES128GCMKeyTemplate() *tinkpb.KeyTemplate {
	empty := []byte{}
	return createECDHESKeyTemplate(commonpb.EllipticCurveType_NIST_P256, commonpb.HashType_SHA256,
		commonpb.EcPointFormat_UNCOMPRESSED, aead.AES128GCMKeyTemplate(), empty)
}

// ECDHESAES256GCMKeyTemplate is a KeyTemplate that generates an ECDH P-256 and decapsulation key AES128-GCM key with
// the following parameters:
//  - KEM: ECDH over NIST P-256
//  - DEM: AES256-GCM
//  - KDF: HKDF-HMAC-SHA256 with an empty salt
func ECDHESAES256GCMKeyTemplate() *tinkpb.KeyTemplate {
	empty := []byte{}
	return createECDHESKeyTemplate(commonpb.EllipticCurveType_NIST_P256, commonpb.HashType_SHA256,
		commonpb.EcPointFormat_UNCOMPRESSED, aead.AES256GCMKeyTemplate(), empty)
}

// createEciesAEADHKDFKeyTemplate creates a new ECDHES-AEAD-HKDF key template with the given key
// size in bytes.
func createECDHESKeyTemplate(c commonpb.EllipticCurveType, ht commonpb.HashType, ptfmt commonpb.EcPointFormat,
	dekT *tinkpb.KeyTemplate, salt []byte) *tinkpb.KeyTemplate {
	format := &eciespb.EciesAeadHkdfKeyFormat{
		Params: &eciespb.EciesAeadHkdfParams{
			KemParams: &eciespb.EciesHkdfKemParams{
				CurveType:    c,
				HkdfHashType: ht,
				HkdfSalt:     salt,
			},
			DemParams: &eciespb.EciesAeadDemParams{
				AeadDem: dekT,
			},
			EcPointFormat: ptfmt,
		},
	}

	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		panic("failed to marshal EciesAeadHkdfKeyFormat proto")
	}

	return &tinkpb.KeyTemplate{
		TypeUrl:          ecdhesPrivateKeyTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	}
}
