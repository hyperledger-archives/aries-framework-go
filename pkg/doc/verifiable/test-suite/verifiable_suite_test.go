/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/square/go-jose/v3"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

func main() {
	inputFile := os.Args[len(os.Args)-1]
	vcBytes, readErr := ioutil.ReadFile(inputFile) // nolint:gosec
	if readErr != nil {
		log.Println(fmt.Errorf("cannot open input file %s: %w", inputFile, readErr))
		abort()
	}

	jwt := flag.String("jwt", "", "base64encoded JSON object containing es256kPrivateKeyJwk and rs256PrivateKeyJwk.")
	// todo use jwtAud #371
	flag.String("jwt-aud", "", "indication to use aud attribute in all JWTs")
	jwtNoJws := flag.Bool("jwt-no-jws", false, "indication to suppress the JWS although keys are present")
	jwtPresentation := flag.Bool("jwt-presentation", false, "indication to generate a verifiable presentation")
	jwtDecode := flag.Bool("jwt-decode", false, "indication to generate a credential from a JWT verifiable credential. The input file will be a JWT instead of a JSON-LD file.") // nolint: lll
	isPresentation := flag.Bool("presentation", false, "presentation is passed")
	flag.Parse()

	if *isPresentation {
		// todo support Verifiable Presentations #371
		log.Println("verifiable presentations are not supported")
		abort()
	}

	if *jwt == "" {
		encodeVCToJSON(vcBytes)
		return
	}

	privateKey, publicKey := parseKeys(*jwt)

	if *jwtDecode {
		decodeVCJWTToJSON(vcBytes, publicKey)
	}

	if *jwtPresentation {
		// TODO Encode Verifiable Presentation #371
		log.Println("verifiable presentations are not supported")
		abort()
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
		log.Println(fmt.Errorf("failed to decode credential: %w", err))
		abort()
	}

	jwtClaims, err := credential.JWTClaims(true)
	if err != nil {
		log.Println(fmt.Errorf("verifiable credential encoding to JWT failed: %w", err))
		abort()
	}

	jws, err := jwtClaims.MarshalJWS(verifiable.RS256, privateKey, "any")
	if err != nil {
		log.Println(fmt.Errorf("failed to serialize JWS: %w", err))
		abort()
	}

	fmt.Println(jws)
}

func encodeVCToJWTUnsecured(vcBytes []byte) {
	credential, err := verifiable.NewCredential(vcBytes)
	if err != nil {
		log.Println(fmt.Errorf("failed to decode credential: %w", err))
		abort()
	}

	jwtClaims, err := credential.JWTClaims(true)
	if err != nil {
		log.Println(fmt.Errorf("verifiable credential encoding to JWT failed: %w", err))
		abort()
	}

	jwtUnsecured, err := jwtClaims.MarshalUnsecuredJWT()
	if err != nil {
		log.Println(fmt.Errorf("failed to serialize unsecured JWT: %w", err))
		abort()
	}

	fmt.Println(jwtUnsecured)
}

func decodeVCJWTToJSON(vcBytes []byte, publicKey interface{}) {
	// Asked to decode JWT
	credential, err := verifiable.NewCredential(vcBytes,
		verifiable.WithJWTPublicKeyFetcher(func(issuerID, keyID string) (interface{}, error) {
			return publicKey, nil
		}))
	if err != nil {
		log.Println(fmt.Errorf("failed to decode credential: %w", err))
		abort()
	}
	jsonBytes, err := credential.MarshalJSON()
	if err != nil {
		log.Println(fmt.Errorf("failed to marshall verifiable credential to JSON: %w", err))
		abort()
	}
	fmt.Println(string(jsonBytes))
}

func parseKeys(packedKeys string) (private, public interface{}) {
	// there are several JWKs which are based64
	decodedJwt, err := base64.StdEncoding.DecodeString(packedKeys)
	if err != nil {
		log.Println(fmt.Errorf("cannot decode base64 of JSON containing JWT keys: %w", err))
		abort()
	}

	// found the target JWK
	decodedJwtMap := make(map[string]interface{})
	err = json.Unmarshal(decodedJwt, &decodedJwtMap)
	if err != nil {
		log.Println(fmt.Errorf("failed to decode JSON containing JWT keys: %w", err))
		abort()
	}

	rs256PrivateKeyJwk, exist := decodedJwtMap["rs256PrivateKeyJwk"]
	if !exist {
		log.Println(fmt.Errorf("cannot get rs256PrivateKeyJwk key"))
		abort()
	}

	// marshal found key back to bytes
	jwkBytes, err := json.Marshal(rs256PrivateKeyJwk)
	if err != nil {
		log.Println(fmt.Errorf("JSON marshalling error: %w", err))
		abort()
	}

	jwk := &jose.JSONWebKey{}
	err = jwk.UnmarshalJSON(jwkBytes)
	if err != nil {
		log.Println(fmt.Errorf("JWK unmarshalling error: %w", err))
		abort()
	}

	privateKey, ok := jwk.Key.(*rsa.PrivateKey)
	if !ok {
		log.Println("expected to get *rsa.PrivateKey, but got smth different")
		abort()
	}

	publicKey := &privateKey.PublicKey

	return privateKey, publicKey
}

func encodeVCToJSON(vcBytes []byte) {
	credential, err := verifiable.NewCredential(vcBytes, verifiable.WithNoCustomSchemaCheck())
	if err != nil {
		log.Println(fmt.Errorf("failed to decode credential: %w", err))
		abort()
	}
	encoded, err := credential.MarshalJSON()
	if err != nil {
		log.Println(fmt.Errorf("failed to encode credential: %w", err))
		abort()
	}
	fmt.Println(string(encoded))
}

func abort() {
	os.Exit(1)
}
