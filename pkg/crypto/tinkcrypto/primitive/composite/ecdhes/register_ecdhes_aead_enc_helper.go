/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdhes

import (
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	gcmpb "github.com/google/tink/go/proto/aes_gcm_go_proto"
	chachapb "github.com/google/tink/go/proto/chacha20_poly1305_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	xchachapb "github.com/google/tink/go/proto/xchacha20_poly1305_go_proto"
	"github.com/google/tink/go/subtle/aead"
	"github.com/google/tink/go/tink"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes/subtle"
)

const (
	aesGCMTypeURL            = "type.googleapis.com/google.crypto.tink.AesGcmKey"
	chaCha20Poly1305TypeURL  = "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
	xChaCha20Poly1305TypeURL = "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key"
)

// registerECDHESAEADEncHelper registers a content encryption helper
type registerECDHESAEADEncHelper struct {
	encKeyURL        string
	keyData          []byte
	symmetricKeySize int
	tagSize          int
	ivSize           int
}

var _ subtle.EncrypterHelper = (*registerECDHESAEADEncHelper)(nil)

// newRegisterECDHESAEADEncHelper initializes and returns a registerECDHESAEADEncHelper
func newRegisterECDHESAEADEncHelper(k *tinkpb.KeyTemplate) (*registerECDHESAEADEncHelper, error) {
	var (
		keySize, tagSize, ivSize int
		skf                      []byte
		err                      error
	)

	switch k.TypeUrl {
	case aesGCMTypeURL:
		gcmKeyFormat := new(gcmpb.AesGcmKeyFormat)

		err = proto.Unmarshal(k.Value, gcmKeyFormat)
		if err != nil {
			return nil, fmt.Errorf("registerECDHESAEADEncHelper: failed to unmarshal gcmKeyFormat: %w", err)
		}

		keySize = int(gcmKeyFormat.KeySize)
		tagSize = aead.AESGCMTagSize
		ivSize = aead.AESGCMIVSize

		skf, err = proto.Marshal(gcmKeyFormat)
		if err != nil {
			return nil, fmt.Errorf("registerECDHESAEADEncHelper: failed to serialize key format, error: %w", err)
		}
	case chaCha20Poly1305TypeURL:
		keySize = chacha20poly1305.KeySize
		tagSize = poly1305.TagSize
		ivSize = chacha20poly1305.NonceSize
	case xChaCha20Poly1305TypeURL:
		keySize = chacha20poly1305.KeySize
		tagSize = poly1305.TagSize
		ivSize = chacha20poly1305.NonceSizeX
	default:
		return nil, fmt.Errorf("registerECDHESAEADEncHelper: unsupported AEAD content encryption key type: %s",
			k.TypeUrl)
	}

	km, err := registry.GetKeyManager(k.TypeUrl)
	if err != nil {
		return nil, fmt.Errorf("registerECDHESAEADEncHelper: failed to fetch KeyManager, error: %w", err)
	}

	// skf is nil for (X)Chahcha20Poly1305 km
	key, err := km.NewKey(skf)
	if err != nil {
		return nil, fmt.Errorf("registerECDHESAEADEncHelper: failed to fetch key, error: %w", err)
	}

	sk, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("registerECDHESAEADEncHelper: failed to serialize key, error: %w", err)
	}

	return &registerECDHESAEADEncHelper{
		encKeyURL:        k.TypeUrl,
		keyData:          sk,
		symmetricKeySize: keySize,
		tagSize:          tagSize,
		ivSize:           ivSize,
	}, nil
}

// GetSymmetricKeySize returns the symmetric key size
func (r *registerECDHESAEADEncHelper) GetSymmetricKeySize() int {
	return r.symmetricKeySize
}

// GetTagSize returns the primitive tag size
func (r *registerECDHESAEADEncHelper) GetTagSize() int {
	return r.tagSize
}

// GetIVSize returns the primitive IV size
func (r *registerECDHESAEADEncHelper) GetIVSize() int {
	return r.ivSize
}

// GetAEAD returns the AEAD primitive from the DEM
func (r *registerECDHESAEADEncHelper) GetAEAD(symmetricKeyValue []byte) (tink.AEAD, error) {
	if len(symmetricKeyValue) != r.GetSymmetricKeySize() {
		return nil, fmt.Errorf("symmetric key has incorrect length")
	}

	sk, err := r.getSerializedKey(symmetricKeyValue)
	if err != nil {
		return nil, err
	}

	p, err := registry.Primitive(r.encKeyURL, sk)
	if err != nil {
		return nil, err
	}

	g, ok := p.(tink.AEAD)
	if !ok {
		return nil, fmt.Errorf("invalid primitive")
	}

	return g, nil
}

func (r *registerECDHESAEADEncHelper) getSerializedKey(symmetricKeyValue []byte) ([]byte, error) {
	var (
		sk  []byte
		err error
	)

	switch r.encKeyURL {
	case aesGCMTypeURL:
		sk, err = r.getSerializedAESGCMKey(symmetricKeyValue)
		if err != nil {
			return nil, fmt.Errorf("registerECDHESAEADEncHelper: failed to serialize key, error: %w", err)
		}
	case chaCha20Poly1305TypeURL:
		chachaKey := new(chachapb.ChaCha20Poly1305Key)

		err = proto.Unmarshal(r.keyData, chachaKey)
		if err != nil {
			return nil, fmt.Errorf("registerECDHESAEADEncHelper: failed to unmarshal chacha key: %w", err)
		}

		chachaKey.KeyValue = symmetricKeyValue

		sk, err = proto.Marshal(chachaKey)
		if err != nil {
			return nil, fmt.Errorf("registerECDHESAEADEncHelper: failed to serialize key, error: %w", err)
		}
	case xChaCha20Poly1305TypeURL:
		xChachaKey := new(xchachapb.XChaCha20Poly1305Key)

		err = proto.Unmarshal(r.keyData, xChachaKey)
		if err != nil {
			return nil, fmt.Errorf("registerECDHESAEADEncHelper: failed to unmarshal xchacha key: %w", err)
		}

		xChachaKey.KeyValue = symmetricKeyValue

		sk, err = proto.Marshal(xChachaKey)
		if err != nil {
			return nil, fmt.Errorf("registerECDHESAEADEncHelper: failed to serialize key, error: %w", err)
		}
	default:
		return nil, fmt.Errorf("registerECDHESAEADEncHelper: unsupported AEAD content encryption key type: %s",
			r.encKeyURL)
	}

	return sk, err
}

func (r *registerECDHESAEADEncHelper) getSerializedAESGCMKey(symmetricKeyValue []byte) ([]byte, error) {
	gcmKey := new(gcmpb.AesGcmKey)

	err := proto.Unmarshal(r.keyData, gcmKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal gcmKeyFormat: %w", err)
	}

	gcmKey.KeyValue = symmetricKeyValue

	return proto.Marshal(gcmKey)
}
