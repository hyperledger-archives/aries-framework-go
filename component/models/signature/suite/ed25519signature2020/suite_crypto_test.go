/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package ed25519signature2020

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/component/kmscrypto/mock/kms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite"
	sigverifier "github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock/storage"
	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"
)

func TestNewCryptoSignerAndVerifier(t *testing.T) {
	lKMS := createKMS(t)

	kid, kh := createKeyHandle(lKMS, kmsapi.ED25519Type)

	tinkCrypto, err := tinkcrypto.New()
	if err != nil {
		panic("failed to create tinkcrypto")
	}

	doc := []byte("test doc")

	suiteSigner := suite.NewCryptoSigner(tinkCrypto, kh)
	suiteVerifier := suite.NewCryptoVerifier(&Crypto{
		Crypto:   tinkCrypto,
		localKMS: lKMS,
	})

	ss := New(suite.WithSigner(suiteSigner), suite.WithVerifier(suiteVerifier))

	docSig, err := ss.Sign(doc)
	if err != nil {
		panic("failed to create a signature")
	}

	pubKeyBytes, _, err := lKMS.ExportPubKeyBytes(kid)
	if err != nil {
		panic("failed to export public key bytes")
	}

	pubKey := &sigverifier.PublicKey{
		Type:  kmsapi.ED25519,
		Value: pubKeyBytes,
	}

	err = ss.Verify(pubKey, doc, docSig)
	if err != nil {
		panic("failed to verify signature")
	}
}

// LocalCrypto defines a verifier which is based on Local KMS and Crypto
// which uses keyset.Handle as input for verification.
type Crypto struct {
	*tinkcrypto.Crypto
	localKMS *localkms.LocalKMS
}

func (t *Crypto) Verify(sig, msg []byte, kh interface{}) error {
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

func createKeyHandle(kms *localkms.LocalKMS, keyType kmsapi.KeyType) (string, *keyset.Handle) {
	kid, kh, err := kms.Create(keyType)
	if err != nil {
		panic(err)
	}

	return kid, kh.(*keyset.Handle)
}

func createKMS(t *testing.T) *localkms.LocalKMS {
	p, err := mockkms.NewProviderForKMS(storage.NewMockStoreProvider(), &noop.NoLock{})
	require.NoError(t, err)

	k, err := localkms.New("local-lock://custom/master/key/", p)
	require.NoError(t, err)

	return k
}

func mapKeyTypeToKMS(t string) (kmsapi.KeyType, error) {
	switch t {
	case kmsapi.ED25519, "Ed25519VerificationKey2020":
		return kmsapi.ED25519Type, nil
	default:
		return "", fmt.Errorf("unsupported key type: %s", t)
	}
}
