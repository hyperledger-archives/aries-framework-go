/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
)

const (
	securityContext        = "https://w3id.org/security/v2"
	securityContextJWK2020 = "https://trustbloc.github.io/context/vc/credentials-v1.jsonld"
)

const (
	jwtPartsNumber   = 3
	jwtHeaderPart    = 0
	jwtSignaturePart = 2
)

// CreateDetachedJWTHeader creates detached JWT header.
func CreateDetachedJWTHeader(p *Proof) string {
	var jwsAlg string

	// TODO this is a hacky workaround, to be improved
	//  (https://github.com/hyperledger/aries-framework-go/issues/1589)
	switch p.Type {
	case "EcdsaSecp256k1Signature2019":
		jwsAlg = "ES256K"
	case "Ed25519Signature2018":
		jwsAlg = "EdDSA"
	default:
		jwsAlg = p.Type
	}

	jwtHeaderMap := map[string]interface{}{
		"alg":  jwsAlg,
		"b64":  false,
		"crit": []string{"b64"},
	}

	jwtHeaderBytes, err := json.Marshal(jwtHeaderMap)
	if err != nil {
		panic(err)
	}

	return base64.RawURLEncoding.EncodeToString(jwtHeaderBytes)
}

// GetJWTSignature returns signature part of JWT.
func GetJWTSignature(jwt string) ([]byte, error) {
	jwtParts := strings.Split(jwt, ".")
	if len(jwtParts) != jwtPartsNumber || jwtParts[jwtSignaturePart] == "" {
		return nil, errors.New("invalid JWT")
	}

	return base64.RawURLEncoding.DecodeString(jwtParts[jwtSignaturePart])
}

func getJWTHeader(jwt string) (string, error) {
	jwtParts := strings.Split(jwt, ".")
	if len(jwtParts) != jwtPartsNumber {
		return "", errors.New("invalid JWT")
	}

	return jwtParts[jwtHeaderPart], nil
}

// createVerifyJWS creates a data to be used to create/verify a digital signature in the
// form of JSON Web Signature (JWS) with detached content (https://tools.ietf.org/html/rfc7797).
// The algorithm of building the payload is similar to conventional  Create Verify Hash algorithm.
// It differs by using https://w3id.org/security/v2 as context for JSON-LD canonization of both
// JSON and Signature documents and by preliminary JSON-LD compacting of JSON document.
// The current implementation is based on the https://github.com/digitalbazaar/jsonld-signatures.
func createVerifyJWS(suite signatureSuite, jsonldDoc map[string]interface{}, p *Proof,
	opts ...jsonld.ProcessorOpts) ([]byte, error) {
	proofOptions := p.JSONLdObject()

	canonicalProofOptions, err := prepareJWSProof(suite, proofOptions, opts...)
	if err != nil {
		return nil, err
	}

	proofOptionsDigest := suite.GetDigest(canonicalProofOptions)

	canonicalDoc, err := prepareDocumentForJWS(suite, jsonldDoc, opts...)
	if err != nil {
		return nil, err
	}

	docDigest := suite.GetDigest(canonicalDoc)

	verifyData := append(proofOptionsDigest, docDigest...)

	jwtHeader, err := getJWTHeader(p.JWS)
	if err != nil {
		return nil, err
	}

	return append([]byte(jwtHeader+"."), verifyData...), nil
}

func prepareJWSProof(suite signatureSuite, proofOptions map[string]interface{},
	opts ...jsonld.ProcessorOpts) ([]byte, error) {
	// TODO proof contexts shouldn't be hardcoded in jws, should be passed in jsonld doc by author [Issue#1833]
	proofOptions[jsonldContext] = []interface{}{securityContext, securityContextJWK2020}
	proofOptionsCopy := make(map[string]interface{}, len(proofOptions))

	for key, value := range proofOptions {
		proofOptionsCopy[key] = value
	}

	delete(proofOptionsCopy, jsonldJWS)
	delete(proofOptionsCopy, jsonldProofValue)

	return suite.GetCanonicalDocument(proofOptionsCopy, opts...)
}

func prepareDocumentForJWS(suite signatureSuite, jsonldObject map[string]interface{},
	opts ...jsonld.ProcessorOpts) ([]byte, error) {
	// copy document object without proof
	doc := GetCopyWithoutProof(jsonldObject)

	if suite.CompactProof() {
		docCompacted, err := getCompactedWithSecuritySchema(doc, opts...)
		if err != nil {
			return nil, err
		}

		doc = docCompacted
	}

	// build canonical document
	return suite.GetCanonicalDocument(doc, opts...)
}

func getCompactedWithSecuritySchema(docMap map[string]interface{},
	opts ...jsonld.ProcessorOpts) (map[string]interface{}, error) {
	var contextMap map[string]interface{}

	err := json.Unmarshal([]byte(securityJSONLD), &contextMap)
	if err != nil {
		return nil, err
	}

	return jsonld.Default().Compact(docMap, contextMap, opts...)
}

// cached value from https://w3id.org/security/v2
const securityJSONLD = `
{
  "@context": [{
    "@version": 1.1
  }, "https://w3id.org/security/v1", {
    "AesKeyWrappingKey2019": "sec:AesKeyWrappingKey2019",
    "DeleteKeyOperation": "sec:DeleteKeyOperation",
    "DeriveSecretOperation": "sec:DeriveSecretOperation",
    "Ed25519Signature2018": "sec:Ed25519Signature2018",
    "Ed25519VerificationKey2018": "sec:Ed25519VerificationKey2018",
    "EquihashProof2018": "sec:EquihashProof2018",
    "ExportKeyOperation": "sec:ExportKeyOperation",
    "GenerateKeyOperation": "sec:GenerateKeyOperation",
    "KmsOperation": "sec:KmsOperation",
    "RevokeKeyOperation": "sec:RevokeKeyOperation",
    "RsaSignature2018": "sec:RsaSignature2018",
    "RsaVerificationKey2018": "sec:RsaVerificationKey2018",
    "Sha256HmacKey2019": "sec:Sha256HmacKey2019",
    "SignOperation": "sec:SignOperation",
    "UnwrapKeyOperation": "sec:UnwrapKeyOperation",
    "VerifyOperation": "sec:VerifyOperation",
    "WrapKeyOperation": "sec:WrapKeyOperation",
    "X25519KeyAgreementKey2019": "sec:X25519KeyAgreementKey2019",

    "allowedAction": "sec:allowedAction",
    "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
    "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"},
    "capability": {"@id": "sec:capability", "@type": "@id"},
    "capabilityAction": "sec:capabilityAction",
    "capabilityChain": {"@id": "sec:capabilityChain", "@type": "@id", "@container": "@list"},
    "capabilityDelegation": {"@id": "sec:capabilityDelegationMethod", "@type": "@id", "@container": "@set"},
    "capabilityInvocation": {"@id": "sec:capabilityInvocationMethod", "@type": "@id", "@container": "@set"},
    "caveat": {"@id": "sec:caveat", "@type": "@id", "@container": "@set"},
    "challenge": "sec:challenge",
    "ciphertext": "sec:ciphertext",
    "controller": {"@id": "sec:controller", "@type": "@id"},
    "delegator": {"@id": "sec:delegator", "@type": "@id"},
    "equihashParameterK": {"@id": "sec:equihashParameterK", "@type": "xsd:integer"},
    "equihashParameterN": {"@id": "sec:equihashParameterN", "@type": "xsd:integer"},
    "invocationTarget": {"@id": "sec:invocationTarget", "@type": "@id"},
    "invoker": {"@id": "sec:invoker", "@type": "@id"},
    "jws": "sec:jws",
    "keyAgreement": {"@id": "sec:keyAgreementMethod", "@type": "@id", "@container": "@set"},
    "kmsModule": {"@id": "sec:kmsModule"},
    "parentCapability": {"@id": "sec:parentCapability", "@type": "@id"},
    "plaintext": "sec:plaintext",
    "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
    "proofPurpose": {"@id": "sec:proofPurpose", "@type": "@vocab"},
    "proofValue": "sec:proofValue",
    "referenceId": "sec:referenceId",
    "unwrappedKey": "sec:unwrappedKey",
    "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"},
    "verifyData": "sec:verifyData",
    "wrappedKey": "sec:wrappedKey"
  }]
}
`
