/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0

This is not actually a test but rather a stand-alone generator application
that is used by VC Test Suite (https://github.com/w3c/vc-test-suite).
To run VC Test Suite, execute `make vc-test-suite`.
*/

package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/square/go-jose/v3"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

var logger = log.New("aries-framework/doc/verifiable/test-suite")

func main() {
	inputFile := os.Args[len(os.Args)-1]
	vcBytes, readErr := ioutil.ReadFile(inputFile) // nolint:gosec
	if readErr != nil {
		abort("cannot open input file %s: %v", inputFile, readErr)
	}

	jwt := flag.String("jwt", "", "base64encoded JSON object containing es256kPrivateKeyJwk and rs256PrivateKeyJwk.")
	// todo use jwtAud #483
	flag.String("jwt-aud", "", "indication to use aud attribute in all JWTs")
	jwtNoJws := flag.Bool("jwt-no-jws", false, "indication to suppress the JWS although keys are present")
	jwtPresentation := flag.Bool("jwt-presentation", false, "indication to generate a verifiable presentation")
	jwtDecode := flag.Bool("jwt-decode", false, "indication to generate a credential from a JWT verifiable credential. The input file will be a JWT instead of a JSON-LD file.") // nolint: lll
	isPresentation := flag.Bool("presentation", false, "presentation is passed")
	flag.Parse()

	if *jwt == "" {
		if *isPresentation {
			encodeVPToJSON(vcBytes)
		} else {
			encodeVCToJSON(vcBytes)
		}
		return
	}

	if *jwtPresentation {
		// TODO Encode Verifiable Presentation #483
		abort("verifiable presentations are not supported")
	}

	privateKey, publicKey := parseKeys(*jwt)

	if *jwtDecode {
		decodeVCJWTToJSON(vcBytes, publicKey)
	}

	if *jwtNoJws {
		encodeVCToJWTUnsecured(vcBytes)
		return
	}

	// Asked to just encode credential
	encodeVCToJWS(vcBytes, privateKey)
}

func encodeVCToJWS(vcBytes []byte, privateKey interface{}) {
	credential, err := verifiable.NewCredential(vcBytes)
	if err != nil {
		abort("failed to decode credential: %v", err)
	}

	jwtClaims, err := credential.JWTClaims(true)
	if err != nil {
		abort("verifiable credential encoding to JWT failed: %v", err)
	}

	jws, err := jwtClaims.MarshalJWS(verifiable.RS256, privateKey, "any")
	if err != nil {
		abort("failed to serialize JWS: %v", err)
	}

	fmt.Println(jws)
}

func encodeVCToJWTUnsecured(vcBytes []byte) {
	credential, err := verifiable.NewCredential(vcBytes)
	if err != nil {
		abort("failed to decode credential: %v", err)
	}

	jwtClaims, err := credential.JWTClaims(true)
	if err != nil {
		abort("verifiable credential encoding to JWT failed: %v", err)
	}

	jwtUnsecured, err := jwtClaims.MarshalUnsecuredJWT()
	if err != nil {
		abort("failed to serialize unsecured JWT: %v", err)
	}

	fmt.Println(jwtUnsecured)
}

func decodeVCJWTToJSON(vcBytes []byte, publicKey interface{}) {
	// Asked to decode JWT
	credential, err := verifiable.NewCredential(vcBytes,
		verifiable.WithJWSDecoding(func(issuerID, keyID string) (interface{}, error) {
			return publicKey, nil
		}))
	if err != nil {
		abort("failed to decode credential: %v", err)
	}
	jsonBytes, err := credential.MarshalJSON()
	if err != nil {
		abort("failed to marshall verifiable credential to JSON: %v", err)
	}
	fmt.Println(string(jsonBytes))
}

func parseKeys(packedKeys string) (private, public interface{}) {
	// there are several JWKs which are based64
	decodedJwt, err := base64.StdEncoding.DecodeString(packedKeys)
	if err != nil {
		abort("cannot decode base64 of JSON containing JWT keys: %v", err)
	}

	// found the target JWK
	decodedJwtMap := make(map[string]interface{})
	err = json.Unmarshal(decodedJwt, &decodedJwtMap)
	if err != nil {
		abort("failed to decode JSON containing JWT keys: %v", err)
	}

	rs256PrivateKeyJwk, exist := decodedJwtMap["rs256PrivateKeyJwk"]
	if !exist {
		abort("cannot get rs256PrivateKeyJwk key")
	}

	// marshal found key back to bytes
	jwkBytes, err := json.Marshal(rs256PrivateKeyJwk)
	if err != nil {
		abort("JSON marshalling error: %v", err)
	}

	jwk := &jose.JSONWebKey{}
	err = jwk.UnmarshalJSON(jwkBytes)
	if err != nil {
		abort("JWK unmarshalling error: %v", err)
	}

	privateKey, ok := jwk.Key.(*rsa.PrivateKey)
	if !ok {
		abort("expected to get *rsa.PrivateKey, but got smth different")
	}

	publicKey := &privateKey.PublicKey

	return privateKey, publicKey
}

func encodeVCToJSON(vcBytes []byte) {
	credential, err := verifiable.NewCredential(vcBytes, verifiable.WithNoCustomSchemaCheck())
	if err != nil {
		abort("failed to decode credential: %v", err)
	}
	encoded, err := credential.MarshalJSON()
	if err != nil {
		abort("failed to encode credential: %v", err)
	}
	fmt.Println(string(encoded))
}

func encodeVPToJSON(vcBytes []byte) {
	vp, err := verifiable.NewPresentation(vcBytes)
	if err != nil {
		abort("failed to decode presentation: %v", err)
	}
	encoded, err := vp.MarshalJSON()
	if err != nil {
		abort("failed to encode presentation: %v", err)
	}
	fmt.Println(string(encoded))
}

func abort(msg string, args ...interface{}) {
	logger.Errorf(msg, args...)
	os.Exit(1)
}
