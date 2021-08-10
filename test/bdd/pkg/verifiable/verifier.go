/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
)

// localCryptoVerifier defines a verifier which is based on Local KMS and Crypto
// which uses keyset.Handle as input for verification.
type localCryptoVerifier struct {
	crypto.Crypto
	localKMS *localkms.LocalKMS
}

func newLocalCryptoVerifier(cr crypto.Crypto, localKMS *localkms.LocalKMS) *localCryptoVerifier {
	return &localCryptoVerifier{
		Crypto:   cr,
		localKMS: localKMS,
	}
}

func (t *localCryptoVerifier) Verify(sig, msg []byte, kh interface{}) error {
	pubKey, ok := kh.(*sigverifier.PublicKey)
	if !ok {
		return errors.New("bad key handle format")
	}

	kmsKeyType, err := mapPublicKeyToKMSKeyType(pubKey)
	if err != nil {
		return err
	}

	handle, err := t.localKMS.PubKeyBytesToHandle(pubKey.Value, kmsKeyType)
	if err != nil {
		return err
	}

	return t.Crypto.Verify(sig, msg, handle)
}

func mapPublicKeyToKMSKeyType(pubKey *sigverifier.PublicKey) (kms.KeyType, error) {
	switch pubKey.Type {
	case "Ed25519VerificationKey2018":
		return kms.ED25519Type, nil
	case "JwsVerificationKey2020":
		return mapJWKToKMSKeyType(pubKey.JWK)
	default:
		return "", fmt.Errorf("unsupported key type: %s", pubKey.Type)
	}
}

func mapJWKToKMSKeyType(j *jwk.JWK) (kms.KeyType, error) {
	switch j.Kty {
	case "OKP":
		return kms.ED25519Type, nil
	case "EC":
		switch j.Crv {
		case "P-256":
			return kms.ECDSAP256TypeIEEEP1363, nil
		case "P-384":
			return kms.ECDSAP384TypeIEEEP1363, nil
		case "P-521":
			return kms.ECDSAP521TypeIEEEP1363, nil
		}
	}

	return "", fmt.Errorf("unsupported JWK: %v", j)
}
