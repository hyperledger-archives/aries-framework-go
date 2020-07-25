/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/golang/protobuf/proto"
	aead "github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/core/registry"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	gcmpb "github.com/google/tink/go/proto/aes_gcm_go_proto"
	chachapb "github.com/google/tink/go/proto/chacha20_poly1305_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	xchachapb "github.com/google/tink/go/proto/xchacha20_poly1305_go_proto"
	"github.com/google/tink/go/tink"
	"github.com/square/go-jose/v3"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

const (
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
	encKeyURL        string
	keyData          []byte
	symmetricKeySize int
	tagSize          int
	ivSize           int
	marshalFunc      marshalFunc
}

var _ EncrypterHelper = (*RegisterCompositeAEADEncHelper)(nil)

// NewRegisterCompositeAEADEncHelper initializes and returns a RegisterCompositeAEADEncHelper.
func NewRegisterCompositeAEADEncHelper(k *tinkpb.KeyTemplate) (*RegisterCompositeAEADEncHelper, error) {
	var (
		keySize, tagSize, ivSize int
		skf                      []byte
		err                      error
	)

	switch k.TypeUrl {
	case AESGCMTypeURL:
		gcmKeyFormat := new(gcmpb.AesGcmKeyFormat)

		err = proto.Unmarshal(k.Value, gcmKeyFormat)
		if err != nil {
			return nil, fmt.Errorf("compositeAEADEncHelper: failed to unmarshal gcmKeyFormat: %w", err)
		}

		keySize = int(gcmKeyFormat.KeySize)
		tagSize = aead.AESGCMTagSize
		ivSize = aead.AESGCMIVSize

		skf, err = proto.Marshal(gcmKeyFormat)
		if err != nil {
			return nil, fmt.Errorf("compositeAEADEncHelper: failed to serialize key format, error: %w", err)
		}
	case ChaCha20Poly1305TypeURL:
		keySize = chacha20poly1305.KeySize
		tagSize = poly1305.TagSize
		ivSize = chacha20poly1305.NonceSize
	case XChaCha20Poly1305TypeURL:
		keySize = chacha20poly1305.KeySize
		tagSize = poly1305.TagSize
		ivSize = chacha20poly1305.NonceSizeX
	default:
		return nil, fmt.Errorf("compositeAEADEncHelper: unsupported AEAD content encryption key type: %s",
			k.TypeUrl)
	}

	km, err := registry.GetKeyManager(k.TypeUrl)
	if err != nil {
		return nil, fmt.Errorf("compositeAEADEncHelper: failed to fetch KeyManager, error: %w", err)
	}

	// skf is nil for (X)Chahcha20Poly1305 km
	key, err := km.NewKey(skf)
	if err != nil {
		return nil, fmt.Errorf("compositeAEADEncHelper: failed to fetch key, error: %w", err)
	}

	sk, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("compositeAEADEncHelper: failed to serialize key, error: %w", err)
	}

	return &RegisterCompositeAEADEncHelper{
		encKeyURL:        k.TypeUrl,
		keyData:          sk,
		symmetricKeySize: keySize,
		tagSize:          tagSize,
		ivSize:           ivSize,
		marshalFunc:      json.Marshal,
	}, nil
}

// GetSymmetricKeySize returns the symmetric key size.
func (r *RegisterCompositeAEADEncHelper) GetSymmetricKeySize() int {
	return r.symmetricKeySize
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

func (r *RegisterCompositeAEADEncHelper) getSerializedKey(symmetricKeyValue []byte) ([]byte, error) {
	var (
		sk  []byte
		err error
	)

	switch r.encKeyURL {
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

// BuildEncData will build the []byte representing the ciphertext sent to the end user as a result of the Composite
// Encryption primitive execution.
func (r *RegisterCompositeAEADEncHelper) BuildEncData(eAlg string, recipientsWK []*RecipientWrappedKey,
	ct, singleRecipientAAD []byte) ([]byte, error) {
	tagSize := r.GetTagSize()
	ivSize := r.GetIVSize()
	iv := ct[:ivSize]
	ctAndTag := ct[ivSize:]
	tagOffset := len(ctAndTag) - tagSize

	encData := &EncryptedData{
		EncAlg:             eAlg,
		Ciphertext:         ctAndTag[:tagOffset],
		IV:                 iv,
		Tag:                ctAndTag[tagOffset:],
		Recipients:         recipientsWK,
		SingleRecipientAAD: singleRecipientAAD,
	}

	return r.marshalFunc(encData)
}

// MergeSingleRecipientHeaders for single recipient encryption, recipient header info is available in the key, update
// AAD with this info and return the marshalled merged result.
func (r *RegisterCompositeAEADEncHelper) MergeSingleRecipientHeaders(recipientWK *RecipientWrappedKey,
	aad []byte) ([]byte, error) {
	newAAD, err := base64.RawURLEncoding.DecodeString(string(aad))
	if err != nil {
		return nil, err
	}

	rawHeaders := map[string]json.RawMessage{}

	err = json.Unmarshal(newAAD, &rawHeaders)
	if err != nil {
		return nil, err
	}

	kid, err := r.marshalFunc(recipientWK.KID)
	if err != nil {
		return nil, err
	}

	rawHeaders["kid"] = kid

	alg, err := r.marshalFunc(recipientWK.Alg)
	if err != nil {
		return nil, err
	}

	rawHeaders["alg"] = alg

	mEPK, err := convertRecKeyToMarshalledJWK(recipientWK)
	if err != nil {
		return nil, err
	}

	rawHeaders["epk"] = mEPK

	mAAD, err := r.marshalFunc(rawHeaders)
	if err != nil {
		return nil, err
	}

	return []byte(base64.RawURLEncoding.EncodeToString(mAAD)), nil
}

func convertRecKeyToMarshalledJWK(rec *RecipientWrappedKey) ([]byte, error) {
	var c elliptic.Curve

	c, err := hybrid.GetCurve(rec.EPK.Curve)
	if err != nil {
		return nil, err
	}

	recJWK := jose.JSONWebKey{
		KeyID: rec.KID,
		Use:   "enc",
		Key: &ecdsa.PublicKey{
			Curve: c,
			X:     new(big.Int).SetBytes(rec.EPK.X),
			Y:     new(big.Int).SetBytes(rec.EPK.Y),
		},
	}

	return recJWK.MarshalJSON()
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
