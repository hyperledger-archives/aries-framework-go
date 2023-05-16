/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3/json"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

func getTestKeyResolver(pubKey *verifier.PublicKey, err error) KeyResolver {
	return KeyResolverFunc(func(string, string) (*verifier.PublicKey, error) {
		return pubKey, err
	})
}

func TestNewVerifier(t *testing.T) {
	r := require.New(t)

	validHeaders := map[string]interface{}{
		"alg": "EdDSA",
		"kid": "did:123#key1",
	}

	t.Run("Verify JWT signed by EdDSA", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		signer := NewEd25519Signer(privKey)

		token, err := NewSigned(&Claims{Issuer: "Mike"}, validHeaders, signer)
		r.NoError(err)
		jws, err := token.Serialize(false)
		r.NoError(err)

		v := NewVerifier(getTestKeyResolver(
			&verifier.PublicKey{
				Type:  kms.ED25519,
				Value: pubKey,
			}, nil))
		_, err = jose.ParseJWS(jws, v)
		r.NoError(err)
	})

	t.Run("Verify JWT signed by RS256", func(t *testing.T) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		r.NoError(err)

		pubKey := &privKey.PublicKey

		signer := NewRS256Signer(privKey, validHeaders)

		token, err := NewSigned(&Claims{Issuer: "Mike"}, nil, signer)
		r.NoError(err)
		jws, err := token.Serialize(false)
		r.NoError(err)

		v := NewVerifier(getTestKeyResolver(
			&verifier.PublicKey{
				Type:  kms.RSARS256,
				Value: x509.MarshalPKCS1PublicKey(pubKey),
			}, nil))
		_, err = jose.ParseJWS(jws, v)
		r.NoError(err)
	})
}

func TestBasicVerifier_Verify(t *testing.T) { // error corner cases
	r := require.New(t)
	validHeaders := map[string]interface{}{
		"alg": "EdDSA",
		"kid": "did:123#key1",
	}

	validClaims, err := json.Marshal(map[string]interface{}{"iss": "Bob"})
	r.NoError(err)

	// key resolver error
	v := NewVerifier(getTestKeyResolver(nil, errors.New("failed to resolve public key")))
	err = v.Verify(validHeaders, validClaims, nil, nil)
	r.Error(err)
	r.Contains(err.Error(), "failed to resolve public key")
}

func TestVerifyEdDSA(t *testing.T) {
	r := require.New(t)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	signature := ed25519.Sign(privKey, []byte("test message"))

	err = VerifyEdDSA(&verifier.PublicKey{
		Type:  kms.ED25519,
		Value: pubKey,
	}, []byte("test message"), signature)
	r.NoError(err)

	err = VerifyEdDSA(&verifier.PublicKey{
		Type:  kms.ED25519,
		Value: []byte("invalid pub key"),
	}, []byte("test message"), signature)
	r.Error(err)
	r.EqualError(err, "bad ed25519 public key length")

	anotherPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	err = VerifyEdDSA(&verifier.PublicKey{
		Type:  kms.ED25519,
		Value: anotherPubKey,
	}, []byte("test message"), signature)
	r.Error(err)
	r.EqualError(err, "signature doesn't match")
}

func TestVerifyRS256(t *testing.T) {
	r := require.New(t)

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	r.NoError(err)

	hash := crypto.SHA256.New()

	_, err = hash.Write([]byte("test message"))
	r.NoError(err)

	hashed := hash.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed)
	r.NoError(err)

	err = VerifyRS256(&verifier.PublicKey{
		Type:  kms.RSARS256,
		Value: x509.MarshalPKCS1PublicKey(&privKey.PublicKey),
	}, []byte("test message"), signature)
	r.NoError(err)

	anotherPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	r.NoError(err)

	err = VerifyRS256(&verifier.PublicKey{
		Type:  kms.RSARS256,
		Value: x509.MarshalPKCS1PublicKey(&anotherPrivKey.PublicKey),
	}, []byte("test message"), signature)
	r.Error(err)
}

func TestGetVerifier(t *testing.T) {
	type fields struct {
		publicKeyPath   string
		credentialsPath string
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
				credentialsPath: "../../../test/bdd/pkg/verifiable/testdata/interop_credential_4_secp256k1.jwt",
				publicKeyPath:   "../../../test/bdd/pkg/verifiable/testdata/interop_key_secp256k1.jwk",
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
			name: "NewECDSASecp256k1SignatureVerifier_Verify_Error_invalid_key",
			fields: fields{
				credentialsPath: "../../../test/bdd/pkg/verifiable/testdata/interop_credential_4_secp256k1.jwt",
				publicKeyPath:   "../../../test/bdd/pkg/verifiable/testdata/interop_key_ed25519.jwk",
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
				credentialsPath: "../../../test/bdd/pkg/verifiable/testdata/interop_credential_7_secp256r1.jwt",
				publicKeyPath:   "../../../test/bdd/pkg/verifiable/testdata/interop_key_secp256r1.jwk",
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
				credentialsPath: "../../../test/bdd/pkg/verifiable/testdata/interop_credential_10_secp384r1.jwt",
				publicKeyPath:   "../../../test/bdd/pkg/verifiable/testdata/interop_key_secp384r1.jwk",
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
			name: "NewECDSAES256SignatureVerifier_Verify_Error_alg_is_missing",
			fields: fields{
				credentialsPath: "../../../test/bdd/pkg/verifiable/testdata/interop_credential_10_secp384r1.jwt",
				publicKeyPath:   "../../../test/bdd/pkg/verifiable/testdata/interop_key_secp384r1.jwk",
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
			name: "NewECDSAES256SignatureVerifier_Verify_Error_Invalid_alg_in_header",
			fields: fields{
				credentialsPath: "../../../test/bdd/pkg/verifiable/testdata/interop_credential_10_secp384r1.jwt",
				publicKeyPath:   "../../../test/bdd/pkg/verifiable/testdata/interop_key_secp384r1.jwk",
			},
			args: args{
				joseHeaders: jose.Headers{
					"alg": "ES256",
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
			v, err := GetVerifier(publicKey)
			if err != nil {
				t.Errorf("GetVerifier() error = %v", err)
			}
			if err = v.Verify(tt.args.joseHeaders, nil, signingInput, signature); (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
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

func getJWK(jwkBytes []byte) (*jwk.JWK, error) {
	jwkKey := &jwk.JWK{}
	err := jwkKey.UnmarshalJSON(jwkBytes)

	return jwkKey, err
}
