/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pkg/errors"
	gojose "github.com/square/go-jose/v3"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

func TestNewECDSAVerifier(t *testing.T) {
	publicKey := &verifier.PublicKey{
		Type: "TestType",
		JWK: &jwk.JWK{
			JSONWebKey: gojose.JSONWebKey{
				Algorithm: "alg",
			},
			Kty: "kty",
			Crv: "crv",
		},
	}

	type args struct {
		curve     string
		publicKey *verifier.PublicKey
	}

	tests := []struct {
		name string
		args args
		want *JoseECDSAVerifier
	}{
		{
			name: "NewECDSAVerifier secp256k1",
			args: args{
				curve:     "secp256k1",
				publicKey: publicKey,
			},
			want: &JoseECDSAVerifier{
				alg:       "ES256K",
				publicKey: publicKey,
				verifier:  verifier.NewECDSASecp256k1SignatureVerifier(),
			},
		},
		{
			name: "NewECDSAVerifier secp256r1",
			args: args{
				curve:     "secp256r1",
				publicKey: publicKey,
			},
			want: &JoseECDSAVerifier{
				alg:       "ES256",
				publicKey: publicKey,
				verifier:  verifier.NewECDSAES256SignatureVerifier(),
			},
		},
		{
			name: "NewECDSAVerifier secp384r1",
			args: args{
				curve:     "secp384r1",
				publicKey: publicKey,
			},
			want: &JoseECDSAVerifier{
				alg:       "ES384",
				publicKey: publicKey,
				verifier:  verifier.NewECDSAES384SignatureVerifier(),
			},
		},
		{
			name: "NewECDSAVerifier secp521r1",
			args: args{
				curve:     "secp521r1",
				publicKey: publicKey,
			},
			want: &JoseECDSAVerifier{
				alg:       "ES521",
				publicKey: publicKey,
				verifier:  verifier.NewECDSAES521SignatureVerifier(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewECDSAVerifier(tt.args.curve, tt.args.publicKey); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewECDSAVerifier() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJoseECDSAVerifier_Verify(t *testing.T) {
	type fields struct {
		alg             string
		publicKeyPath   string
		credentialsPath string
		verifier        verifier.SignatureVerifier
	}

	type args struct {
		joseHeaders jose.Headers
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "NewECDSASecp256k1SignatureVerifier_Verify_OK",
			fields: fields{
				alg:             "ES256K",
				credentialsPath: "../../../test/bdd/pkg/verifiable/testdata/interop_credential_4_secp256k1.jwt",
				publicKeyPath:   "../../../test/bdd/pkg/verifiable/testdata/interop_key_secp256k1.jwk",
				verifier:        verifier.NewECDSASecp256k1SignatureVerifier(),
			},
			args: args{
				joseHeaders: jose.Headers{
					"alg": "ES256K",
					"kid": "did:example:123#key-1",
					"typ": "JWT",
				},
			},
			wantErr: false,
		},
		{
			name: "NewECDSASecp256k1SignatureVerifier_Verify_Error",
			fields: fields{
				alg:             "ES256K",
				credentialsPath: "../../../test/bdd/pkg/verifiable/testdata/interop_credential_4_secp256k1.jwt",
				publicKeyPath:   "../../../test/bdd/pkg/verifiable/testdata/interop_key_ed25519.jwk",
				verifier:        verifier.NewECDSASecp256k1SignatureVerifier(),
			},
			args: args{
				joseHeaders: jose.Headers{
					"alg": "ES256K",
					"kid": "did:example:123#key-1",
					"typ": "JWT",
				},
			},
			wantErr: true,
		},
		{
			name: "NewECDSAES256SignatureVerifier_Verify_OK",
			fields: fields{
				alg:             "ES256",
				credentialsPath: "../../../test/bdd/pkg/verifiable/testdata/interop_credential_7_secp256r1.jwt",
				publicKeyPath:   "../../../test/bdd/pkg/verifiable/testdata/interop_key_secp256r1.jwk",
				verifier:        verifier.NewECDSAES256SignatureVerifier(),
			},
			args: args{
				joseHeaders: jose.Headers{
					"alg": "ES256",
					"kid": "did:example:123#key-1",
					"typ": "JWT",
				},
			},
			wantErr: false,
		},
		{
			name: "NewECDSAES256SignatureVerifier_Verify_OK",
			fields: fields{
				alg:             "ES384",
				credentialsPath: "../../../test/bdd/pkg/verifiable/testdata/interop_credential_10_secp384r1.jwt",
				publicKeyPath:   "../../../test/bdd/pkg/verifiable/testdata/interop_key_secp384r1.jwk",
				verifier:        verifier.NewECDSAES384SignatureVerifier(),
			},
			args: args{
				joseHeaders: jose.Headers{
					"alg": "ES384",
					"kid": "did:example:123#key-1",
					"typ": "JWT",
				},
			},
			wantErr: false,
		},
		{
			name: "NewECDSAES256SignatureVerifier_Verify_Error",
			fields: fields{
				alg:             "ES384",
				credentialsPath: "../../../test/bdd/pkg/verifiable/testdata/interop_credential_10_secp384r1.jwt",
				publicKeyPath:   "../../../test/bdd/pkg/verifiable/testdata/interop_key_secp384r1.jwk",
				verifier:        verifier.NewECDSAES384SignatureVerifier(),
			},
			args: args{
				joseHeaders: jose.Headers{
					"kid": "did:example:123#key-1",
					"typ": "JWT",
				},
			},
			wantErr: true,
		},
		{
			name: "NewECDSAES256SignatureVerifier_Verify_Error",
			fields: fields{
				alg:             "ES256",
				credentialsPath: "../../../test/bdd/pkg/verifiable/testdata/interop_credential_10_secp384r1.jwt",
				publicKeyPath:   "../../../test/bdd/pkg/verifiable/testdata/interop_key_secp384r1.jwk",
				verifier:        verifier.NewECDSAES384SignatureVerifier(),
			},
			args: args{
				joseHeaders: jose.Headers{
					"alg": "ES384",
					"kid": "did:example:123#key-1",
					"typ": "JWT",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publicKey, err := getPublicKeyFromPath(tt.fields.publicKeyPath)
			if err != nil {
				t.Errorf("getPublicKeyFromPath() error = %v", err)
			}
			signingInput, signature, err := getSigningInputAndSignatureFromPath(tt.fields.credentialsPath)
			if err != nil {
				t.Errorf("getSigningInputAndSignatureFromPath() error = %v", err)
			}
			v := JoseECDSAVerifier{
				alg:       tt.fields.alg,
				publicKey: publicKey,
				verifier:  tt.fields.verifier,
			}
			if err = v.Verify(tt.args.joseHeaders, nil, signingInput, signature); (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func getSigningInputAndSignatureFromPath(credentialsPath string) ([]byte, []byte, error) {
	jwt, err := getJWTFromFile(credentialsPath)
	if err != nil {
		return nil, nil, err
	}

	chunks := strings.Split(jwt, ".")
	signingInput := []byte(fmt.Sprintf("%s.%s", chunks[0], chunks[1]))
	signature, err := base64.RawURLEncoding.DecodeString(chunks[2])

	return signingInput, signature, err
}

type JWTJSONFile struct {
	JWT string `json:"jwt"`
}

func getJWTFromFile(path string) (string, error) {
	bytes, err := ioutil.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", errors.Wrapf(err, "could not read jwt from file: %s", path)
	}

	var jwt JWTJSONFile

	return jwt.JWT, json.Unmarshal(bytes, &jwt)
}

func getPublicKeyFromPath(path string) (*verifier.PublicKey, error) {
	b, err := ioutil.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	jwkKey, err := getJWK(b)
	if err != nil {
		return nil, err
	}

	jwkBytes, err := jwkKey.PublicKeyBytes()

	return &verifier.PublicKey{
		Type:  "JsonWebKey2020",
		Value: jwkBytes,
		JWK:   jwkKey,
	}, err
}

func getJWK(jwkBytes []byte) (*jwk.JWK, error) {
	jwkKey := &jwk.JWK{}
	err := jwkKey.UnmarshalJSON(jwkBytes)

	return jwkKey, err
}
