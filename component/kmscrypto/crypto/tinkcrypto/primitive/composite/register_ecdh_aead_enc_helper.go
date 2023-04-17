/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

import (
	"encoding/json"
	"errors"
	"fmt"

	aead "github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/core/registry"
	gcmpb "github.com/google/tink/go/proto/aes_gcm_go_proto"
	chachapb "github.com/google/tink/go/proto/chacha20_poly1305_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	xchachapb "github.com/google/tink/go/proto/xchacha20_poly1305_go_proto"
	"github.com/google/tink/go/tink"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
	cbchmacpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/aes_cbc_hmac_aead_go_proto"
)

const (
	// AESCBCHMACAEADTypeURL for AESCBC+HMAC AEAD content encryption URL.
	AESCBCHMACAEADTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.AesCbcHmacAeadKey"
	// AESGCMTypeURL for AESGCM content encryption URL identifier.
	AESGCMTypeURL = "type.googleapis.com/google.crypto.tink.AesGcmKey"
	// ChaCha20Poly1305TypeURL for Chacha20Poly1305 content encryption URL identifier.
	ChaCha20Poly1305TypeURL = "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
	// XChaCha20Poly1305TypeURL for XChachaPoly1305 content encryption URL identifier.
	XChaCha20Poly1305TypeURL = "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key"
)

type marshalFunc func(interface{}) ([]byte, error)

// RegisterCompositeAEADEncHelper registers a content encryption helper.
type RegisterCompositeAEADEncHelper struct {
	encKeyURL   string
	keyData     []byte
	tagSize     int
	ivSize      int
	marshalFunc marshalFunc
}

var _ EncrypterHelper = (*RegisterCompositeAEADEncHelper)(nil)

// NewRegisterCompositeAEADEncHelper initializes and returns a RegisterCompositeAEADEncHelper.
//nolint:gocyclo
func NewRegisterCompositeAEADEncHelper(k *tinkpb.KeyTemplate) (*RegisterCompositeAEADEncHelper, error) {
	var (
		tagSize, ivSize int
		skf             []byte
		err             error
	)

	switch k.TypeUrl {
	case AESCBCHMACAEADTypeURL:
		cbcHMACKeyFormat := new(cbchmacpb.AesCbcHmacAeadKeyFormat)

		err = proto.Unmarshal(k.Value, cbcHMACKeyFormat)
		if err != nil {
			return nil, fmt.Errorf("compositeAEADEncHelper: failed to unmarshal cbcHMACKeyFormat: %w", err)
		}

		tagSize = int(cbcHMACKeyFormat.HmacKeyFormat.Params.TagSize)
		ivSize = subtle.AESCBCIVSize

		skf, err = proto.Marshal(cbcHMACKeyFormat)
		if err != nil {
			return nil, fmt.Errorf("compositeAEADEncHelper: failed to serialize cbcHMAC key format, error: %w", err)
		}
	case AESGCMTypeURL:
		gcmKeyFormat := new(gcmpb.AesGcmKeyFormat)

		err = proto.Unmarshal(k.Value, gcmKeyFormat)
		if err != nil {
			return nil, fmt.Errorf("compositeAEADEncHelper: failed to unmarshal gcmKeyFormat: %w", err)
		}

		tagSize = aead.AESGCMTagSize
		ivSize = aead.AESGCMIVSize

		skf, err = proto.Marshal(gcmKeyFormat)
		if err != nil {
			return nil, fmt.Errorf("compositeAEADEncHelper: failed to serialize gcm key format, error: %w", err)
		}
	case ChaCha20Poly1305TypeURL:
		tagSize = poly1305.TagSize
		ivSize = chacha20poly1305.NonceSize

		skf, err = buildChachaSKF(k)
		if err != nil {
			return nil, err
		}
	case XChaCha20Poly1305TypeURL:
		tagSize = poly1305.TagSize
		ivSize = chacha20poly1305.NonceSizeX

		skf, err = buildXChachaSKF(k)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("compositeAEADEncHelper: unsupported AEAD content encryption key type: %s",
			k.TypeUrl)
	}

	return buildRegisterCompositeAEADEncHelper(k, skf, tagSize, ivSize)
}

func buildChachaSKF(k *tinkpb.KeyTemplate) ([]byte, error) {
	chachaKeyFormat := new(chachapb.ChaCha20Poly1305KeyFormat)

	err := proto.Unmarshal(k.Value, chachaKeyFormat)
	if err != nil {
		return nil, fmt.Errorf("compositeAEADEncHelper: failed to unmarshal chachaKeyFormat: %w", err)
	}

	skf, err := proto.Marshal(chachaKeyFormat)
	if err != nil {
		return nil, fmt.Errorf("compositeAEADEncHelper: failed to serialize chacha key format, error: %w", err)
	}

	return skf, nil
}

func buildXChachaSKF(k *tinkpb.KeyTemplate) ([]byte, error) {
	xChachaKeyFormat := new(xchachapb.XChaCha20Poly1305KeyFormat)

	err := proto.Unmarshal(k.Value, xChachaKeyFormat)
	if err != nil {
		return nil, fmt.Errorf("compositeAEADEncHelper: failed to unmarshal xChachaKeyFormat: %w", err)
	}

	skf, err := proto.Marshal(xChachaKeyFormat)
	if err != nil {
		return nil, fmt.Errorf("compositeAEADEncHelper: failed to serialize xChacha key format, error: %w", err)
	}

	return skf, nil
}

func buildRegisterCompositeAEADEncHelper(k *tinkpb.KeyTemplate, skf []byte,
	tagSize, ivSize int) (*RegisterCompositeAEADEncHelper, error) {
	km, err := registry.GetKeyManager(k.TypeUrl)
	if err != nil {
		return nil, fmt.Errorf("compositeAEADEncHelper: failed to fetch KeyManager, error: %w", err)
	}

	key, err := km.NewKey(skf)
	if err != nil {
		return nil, fmt.Errorf("compositeAEADEncHelper: failed to fetch key, error: %w", err)
	}

	sk, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("compositeAEADEncHelper: failed to serialize key, error: %w", err)
	}

	return &RegisterCompositeAEADEncHelper{
		encKeyURL:   k.TypeUrl,
		keyData:     sk,
		tagSize:     tagSize,
		ivSize:      ivSize,
		marshalFunc: json.Marshal,
	}, nil
}

// GetTagSize returns the primitive tag size.
func (r *RegisterCompositeAEADEncHelper) GetTagSize() int {
	return r.tagSize
}

// GetIVSize returns the primitive IV size.
func (r *RegisterCompositeAEADEncHelper) GetIVSize() int {
	return r.ivSize
}

// GetAEAD returns the AEAD primitive from the DEM.
func (r *RegisterCompositeAEADEncHelper) GetAEAD(symmetricKeyValue []byte) (tink.AEAD, error) {
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

func (r *RegisterCompositeAEADEncHelper) getSerializedKey(symmetricKeyValue []byte) ([]byte, error) { //nolint:gocyclo
	var (
		sk  []byte
		err error
	)

	switch r.encKeyURL {
	case AESCBCHMACAEADTypeURL:
		sk, err = r.getSerializedAESCBCHMACKey(symmetricKeyValue)
		if err != nil {
			return nil, fmt.Errorf("registerCompositeAEADEncHelper: failed to serialize key, error: %w", err)
		}
	case AESGCMTypeURL:
		sk, err = r.getSerializedAESGCMKey(symmetricKeyValue)
		if err != nil {
			return nil, fmt.Errorf("registerCompositeAEADEncHelper: failed to serialize key, error: %w", err)
		}
	case ChaCha20Poly1305TypeURL:
		chachaKey := new(chachapb.ChaCha20Poly1305Key)

		err = proto.Unmarshal(r.keyData, chachaKey)
		if err != nil {
			return nil, fmt.Errorf("registerCompositeAEADEncHelper: failed to unmarshal chacha key: %w", err)
		}

		chachaKey.KeyValue = symmetricKeyValue

		sk, err = proto.Marshal(chachaKey)
		if err != nil {
			return nil, fmt.Errorf("registerCompositeAEADEncHelper: failed to serialize key, error: %w", err)
		}
	case XChaCha20Poly1305TypeURL:
		xChachaKey := new(xchachapb.XChaCha20Poly1305Key)

		err = proto.Unmarshal(r.keyData, xChachaKey)
		if err != nil {
			return nil, fmt.Errorf("registerCompositeAEADEncHelper: failed to unmarshal xchacha key: %w", err)
		}

		xChachaKey.KeyValue = symmetricKeyValue

		sk, err = proto.Marshal(xChachaKey)
		if err != nil {
			return nil, fmt.Errorf("registerCompositeAEADEncHelper: failed to serialize key, error: %w", err)
		}
	default:
		return nil, fmt.Errorf("registerCompositeAEADEncHelper: unsupported AEAD content encryption key type: %s",
			r.encKeyURL)
	}

	return sk, err
}

func (r *RegisterCompositeAEADEncHelper) getSerializedAESGCMKey(symmetricKeyValue []byte) ([]byte, error) {
	gcmKey := new(gcmpb.AesGcmKey)

	err := proto.Unmarshal(r.keyData, gcmKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal gcmKeyFormat: %w", err)
	}

	gcmKey.KeyValue = symmetricKeyValue

	return proto.Marshal(gcmKey)
}

func (r *RegisterCompositeAEADEncHelper) getSerializedAESCBCHMACKey(symmetricKeyValue []byte) ([]byte, error) {
	cbcHMACKey := new(cbchmacpb.AesCbcHmacAeadKey)

	err := proto.Unmarshal(r.keyData, cbcHMACKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal cbcHMACKeyFormat: %w", err)
	}

	var (
		keySize int
		twoKeys = 2
	)

	switch len(symmetricKeyValue) {
	case subtle.AES128Size * twoKeys:
		keySize = subtle.AES128Size
	case subtle.AES192Size * twoKeys:
		keySize = subtle.AES192Size
	case subtle.AES256Size + subtle.AES192Size:
		keySize = subtle.AES256Size
	case subtle.AES256Size * twoKeys:
		keySize = subtle.AES256Size
	default:
		return nil, errors.New("AES-CBC+HMAC-SHA key must be either 32, 48, 56 or 64 bytes")
	}

	cbcHMACKey.HmacKey.KeyValue = symmetricKeyValue[:keySize]
	cbcHMACKey.AesCbcKey.KeyValue = symmetricKeyValue[keySize:]

	return proto.Marshal(cbcHMACKey)
}

// BuildEncData will build the []byte representing the ciphertext sent to the end user as a result of the Composite
// Encryption primitive execution.
func (r *RegisterCompositeAEADEncHelper) BuildEncData(ct []byte) ([]byte, error) {
	tagSize := r.GetTagSize()
	ivSize := r.GetIVSize()
	iv := ct[:ivSize]
	ctAndTag := ct[ivSize:]
	tagOffset := len(ctAndTag) - tagSize

	encData := &EncryptedData{
		Ciphertext: ctAndTag[:tagOffset],
		IV:         iv,
		Tag:        ctAndTag[tagOffset:],
	}

	return r.marshalFunc(encData)
}

// BuildDecData will build the []byte representing the ciphertext coming from encData struct returned as a result of
// Composite Encrypt() call to prepare the Composite Decryption primitive execution.
func (r *RegisterCompositeAEADEncHelper) BuildDecData(encData *EncryptedData) []byte {
	iv := encData.IV
	tag := encData.Tag
	ct := encData.Ciphertext
	finalCT := append(iv, ct...)
	finalCT = append(finalCT, tag...)

	return finalCT
}
