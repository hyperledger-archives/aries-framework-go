/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh1pu

import (
	"fmt"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/tink"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	compositepb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto"
	ecdh1pupb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh1pu_aead_go_proto"
)

// AddRecipientsKeys adds recipients keys to the primary key of the keyset handle senderKH and returns an updated handle
// that can be used to perform ECDH1PUEncrypt.Encrypt() calls using the sender key and the added recipients keys.
// senderKH must contain a keyset of private keys. It will return an error if it points to a public key.
func AddRecipientsKeys(senderKH *keyset.Handle, recKeys []*composite.PublicKey) (*keyset.Handle, error) {
	var (
		recPubKeysPb []*compositepb.ECPublicKey
		fnName       = "AddRecipientsKeys"
	)

	for _, r := range recKeys {
		rKeyPb, err := convertPublicKeyToProto(r)
		if err != nil {
			return nil, fmt.Errorf("%s: failed to convert recipient to proto: %w", fnName, err)
		}

		recPubKeysPb = append(recPubKeysPb, rKeyPb)
	}

	return addKeysToHandle(senderKH, recPubKeysPb, fnName)
}

// AddSenderKey adds a sender key to the primary key of the keyset handle recipientKH and returns an updated handle that
// can be used to perform ECDH1PUDecrypt.Decrypt() calls using the recipient key and the added sender key.
// recipientKH must contain a keyset of private keys. It will return an error if it points to a public key.
func AddSenderKey(recipientKH *keyset.Handle, senderKey *composite.PublicKey) (*keyset.Handle, error) {
	var fnName = "AddSenderKey"

	senderKeyPb, err := convertPublicKeyToProto(senderKey)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to convert senderKey to proto: %w", fnName, err)
	}

	return addKeysToHandle(recipientKH, []*compositepb.ECPublicKey{senderKeyPb}, fnName)
}

func addKeysToHandle(kh *keyset.Handle, keysPbs []*compositepb.ECPublicKey, fnName string) (*keyset.Handle, error) {
	_, err := kh.Public()
	if err != nil && strings.Contains(err.Error(), "keyset contains a non-private key") {
		return nil, fmt.Errorf("%s: keyset.Handle points to a public key. It must point to a priviate key",
			fnName)
	}

	memWriter := &keyset.MemReaderWriter{}
	mockMasterLock := &writerLock{}

	ks, idx, err := extractKeySet(kh, memWriter, mockMasterLock, fnName)
	if err != nil {
		return nil, fmt.Errorf("%s: extract keyset failed: %w", fnName, err)
	}

	ecdh1privKeyPb := new(ecdh1pupb.Ecdh1PuAeadPrivateKey)

	err = proto.Unmarshal(ks.Key[idx].KeyData.Value, ecdh1privKeyPb)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to unmarshal recipient private key: %w", fnName, err)
	}

	// finally set the corresponding key in the protobuf, update keyset in memWriter and read it to get an updated
	// *keyset.Handle ready for crypto primitive execution
	switch fnName {
	case "AddRecipientsKeys":
		ecdh1privKeyPb.PublicKey.Params.KwParams.Recipients = keysPbs
		ecdh1privKeyPb.PublicKey.KWD = ecdh1privKeyPb.KeyValue // key wrap using sender key for recipients needs this
	case "AddSenderKey":
		ecdh1privKeyPb.PublicKey.Params.KwParams.Sender = keysPbs[0]
	}

	ks.Key[idx].KeyData.Value, err = proto.Marshal(ecdh1privKeyPb)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal recipient private key: %w", fnName, err)
	}

	memWriter.EncryptedKeyset.EncryptedKeyset, err = proto.Marshal(ks)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal recipient keyset: %w", fnName, err)
	}

	return keyset.Read(memWriter, mockMasterLock)
}

func extractKeySet(kh *keyset.Handle, w keyset.Writer, lock tink.AEAD, fnName string) (*tinkpb.Keyset, int, error) {
	err := kh.Write(w, lock)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: failed to write recipient keyset: %w", fnName, err)
	}

	memWriter, ok := w.(*keyset.MemReaderWriter)
	if !ok {
		return nil, 0, fmt.Errorf("%s: invalid writer instance", fnName)
	}

	ks := new(tinkpb.Keyset)

	err = proto.Unmarshal(memWriter.EncryptedKeyset.EncryptedKeyset, ks)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: failed to unmarshal recipient keyset: %w", fnName, err)
	}

	idx := -1

	for i, k := range ks.Key {
		if ks.PrimaryKeyId == k.KeyId && k.Status == tinkpb.KeyStatusType_ENABLED && k.KeyData.TypeUrl ==
			ecdh1puAESPrivateKeyTypeURL {
			idx = i
			break
		}
	}

	if idx < 0 {
		return nil, 0, fmt.Errorf("%s: primary key not found in keyset", fnName)
	}

	return ks, idx, nil
}

type writerLock struct{}

// Encrypt plaintext, internal function
func (n *writerLock) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	return plaintext, nil
}

// Decrypt ciphertext, internal
func (n *writerLock) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	return ciphertext, nil
}
