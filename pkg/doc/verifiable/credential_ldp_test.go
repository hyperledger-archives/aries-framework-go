/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
)

func TestNewCredentialFromLinkedDataProof_Ed25519Signature2018(t *testing.T) {
	r := require.New(t)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	sigSuite := ed25519signature2018.New(
		suite.WithSigner(getEd25519TestSigner(privKey)),
		suite.WithVerifier(&ed25519signature2018.PublicKeyVerifier{}))

	ldpContext := &LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		SignatureRepresentation: SignatureProofValue,
		Suite:                   sigSuite,
		VerificationMethod:      "did:example:123456#key1",
	}

	vc, _, err := NewCredential([]byte(validCredential))
	r.NoError(err)

	err = vc.AddLinkedDataProof(ldpContext)
	r.NoError(err)

	vcBytes, err := json.Marshal(vc)
	r.NoError(err)

	vcWithLdp, _, err := NewCredential(vcBytes,
		WithEmbeddedSignatureSuites(sigSuite),
		WithPublicKeyFetcher(SingleKey(pubKey, kms.ED25519)))
	r.NoError(err)
	r.Equal(vc, vcWithLdp)
}

func TestNewCredentialFromLinkedDataProof_JsonWebSignature2020_Ed25519(t *testing.T) {
	r := require.New(t)

	//nolint:lll
	vcFromTransmute := `
 {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "http://example.gov/credentials/3732",
      "type": [
        "VerifiableCredential",
        "UniversityDegreeCredential"
      ],
      "issuer": "did:web:vc.transmute.world",
      "issuanceDate": "2020-03-10T04:24:12.164Z",
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "degree": {
          "type": "BachelorDegree",
          "name": "Bachelor of Science and Arts"
        }
      },
      "proof": {
        "type": "JsonWebSignature2020",
        "created": "2020-03-23T10:06:49Z",
        "verificationMethod": "did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
        "proofPurpose": "assertionMethod",
        "jws": "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJFZERTQSJ9..oWfz-jYc_pb5sLmh_2tpDJoLm9uCvUfbuN2yA40MgZcfuFqyhTi0fQj785c0GXPwT4yaZAEQY8rQJacM2MSzBg"
      }
    }
`
	key := `
{
      "crv": "Ed25519",
      "x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ",
      "d": "tP7VWE16yMQWUO2G250yvoevfbfxY25GjHglTP3ZOyU",
      "kty": "OKP",
      "kid": "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A"
    }
`

	var jsonWebKey jose.JSONWebKey
	err := json.Unmarshal([]byte(key), &jsonWebKey)
	r.NoError(err)

	pubKeyBytes, ok := jsonWebKey.Public().Key.(ed25519.PublicKey)
	r.True(ok)

	sigSuite := jsonwebsignature2020.New(
		suite.WithVerifier(suite.NewCryptoVerifier(createLocalCrypto())),
		suite.WithCompactProof())

	vcWithLdp, _, err := NewCredential([]byte(vcFromTransmute),
		WithEmbeddedSignatureSuites(sigSuite),
		WithPublicKeyFetcher(SingleKey(pubKeyBytes, kms.ED25519)))
	r.NoError(err)
	r.NotNil(t, vcWithLdp)
}

func TestNewCredentialFromLinkedDataProof_JsonWebSignature2020_ecdsaP256(t *testing.T) {
	r := require.New(t)
	//nolint:lll
	vcFromTransmute := `
{
  "@context": [
	"https://www.w3.org/2018/credentials/v1",
	"https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "http://example.gov/credentials/3732",
  "type": [
	"VerifiableCredential",
	"UniversityDegreeCredential"
  ],
  "issuer": "did:web:vc.transmute.world",
  "issuanceDate": "2020-03-10T04:24:12.164Z",
  "credentialSubject": {
	"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
	"degree": {
	  "type": "BachelorDegree",
	  "name": "Bachelor of Science and Arts"
	}
  },
  "proof": {
	"type": "JsonWebSignature2020",
	"created": "2020-03-27T16:12:55Z",
	"verificationMethod": "did:example:123#_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw",
	"proofPurpose": "assertionMethod",
	"jws": "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJFUzI1NiJ9..rxj1M_yPYhn5Eo9IGGdQKVmF8dgzhaxaForvuGc6lllrSZ_VIUPcK57Odq2KPHtUAra4_1LtbCihSbaLogyACA"
  }
}
`

	ecdsaP256Key := `
{
  "crv": "P-256",
  "x": "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8",
  "y": "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4",
  "d": "jo3AJc3hrH_Ms39W_4dAl2Qm3gAs9JrNijO6n30sIWc",
  "kty": "EC",
  "kid": "_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw"
}
`

	var jsonWebKey jose.JSONWebKey

	err := json.Unmarshal([]byte(ecdsaP256Key), &jsonWebKey)
	r.NoError(err)

	pubKey, ok := jsonWebKey.Public().Key.(*ecdsa.PublicKey)
	r.True(ok)

	pubKeyBytes := elliptic.Marshal(pubKey, pubKey.X, pubKey.Y)

	sigSuite := jsonwebsignature2020.New(
		// TODO use suite.NewCryptoVerifier(createLocalCrypto()) verifier (as it's done in Ed25519 test above)
		//   (https://github.com/hyperledger/aries-framework-go/issues/1534)
		suite.WithVerifier(&jsonwebsignature2020.PublicKeyVerifierP256{}),
		suite.WithCompactProof())

	vcWithLdp, _, err := NewCredential([]byte(vcFromTransmute),
		WithEmbeddedSignatureSuites(sigSuite),
		WithPublicKeyFetcher(SingleKey(pubKeyBytes, kms.ECDSAP256)))
	r.NoError(err)
	r.NotNil(t, vcWithLdp)
}

func TestCredential_AddLinkedDataProof(t *testing.T) {
	r := require.New(t)

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	t.Run("Add a valid JWS Linked Data proof to VC", func(t *testing.T) {
		vc, _, err := NewCredential([]byte(validCredential))
		r.NoError(err)

		originalVCMap, err := toMap(vc)
		r.NoError(err)

		err = vc.AddLinkedDataProof(&LinkedDataProofContext{
			SignatureType:           "Ed25519Signature2018",
			SignatureRepresentation: SignatureJWS,
			Suite:                   ed25519signature2018.New(suite.WithSigner(getEd25519TestSigner(privKey))),
		})
		r.NoError(err)

		vcMap, err := toMap(vc)
		r.NoError(err)

		r.Contains(vcMap, "proof")
		vcProof := vcMap["proof"]
		vcProofMap, ok := vcProof.(map[string]interface{})
		r.True(ok)
		r.Contains(vcProofMap, "created")
		r.Contains(vcProofMap, "jws")
		r.Equal("Ed25519Signature2018", vcProofMap["type"])

		// check that only "proof" element was added as a result of AddLinkedDataProof().
		delete(vcMap, "proof")
		r.Equal(originalVCMap, vcMap)
	})

	t.Run("Add invalid Linked Data proof to VC", func(t *testing.T) {
		vc, _, err := NewCredential([]byte(validCredential))
		require.NoError(t, err)

		vc.CustomFields = map[string]interface{}{
			"invalidField": make(chan int),
		}

		err = vc.AddLinkedDataProof(&LinkedDataProofContext{
			SignatureType:           "Ed25519Signature2018",
			SignatureRepresentation: SignatureProofValue,
			Suite:                   ed25519signature2018.New(suite.WithSigner(getEd25519TestSigner(privKey))),
		})
		r.Error(err)

		vc.CustomFields = nil
		ldpContextWithMissingSignatureType := &LinkedDataProofContext{
			Suite:                   ed25519signature2018.New(suite.WithSigner(getEd25519TestSigner(privKey))),
			SignatureRepresentation: SignatureProofValue,
		}

		err = vc.AddLinkedDataProof(ldpContextWithMissingSignatureType)
		r.Error(err)
	})
}

func createLocalCrypto() crypto.Crypto {
	lKMS := createKMS()

	tinkCrypto, err := tinkcrypto.New()
	if err != nil {
		panic("failed to create tinkcrypto")
	}

	return &LocalCrypto{
		Crypto:   tinkCrypto,
		localKMS: lKMS,
	}
}

// LocalCrypto defines a verifier which is based on Local KMS and Crypto
// which uses keyset.Handle as input for verification.
type LocalCrypto struct {
	*tinkcrypto.Crypto
	localKMS *localkms.LocalKMS
}

func (t *LocalCrypto) Verify(sig, msg []byte, kh interface{}) error {
	pubKey, ok := kh.(*sigverifier.PublicKey)
	if !ok {
		return errors.New("bad key handle format")
	}

	kmsKeyType, err := mapKeyTypeToKMS(pubKey.Type)
	if err != nil {
		return err
	}

	handle, err := t.localKMS.PubKeyBytesToHandle(pubKey.Value, kmsKeyType)
	if err != nil {
		return err
	}

	return t.Crypto.Verify(sig, msg, handle)
}

func mapKeyTypeToKMS(t string) (kms.KeyType, error) {
	switch t {
	case kms.ECDSAP256:
		return kms.ECDSAP256Type, nil
	case kms.ED25519:
		return kms.ED25519Type, nil
	default:
		return "", fmt.Errorf("unsupported key type: %s", t)
	}
}

func createKMS() *localkms.LocalKMS {
	p := mockkms.NewProvider(storage.NewMockStoreProvider(), &noop.NoLock{})

	k, err := localkms.New("local-lock://custom/master/key/", p)
	if err != nil {
		panic(err)
	}

	return k
}
