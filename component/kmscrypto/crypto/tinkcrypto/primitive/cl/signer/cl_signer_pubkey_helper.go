//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"bytes"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	clproto "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/cl_go_proto"
)

// ExportCredDefPubKey will export corresponding pubKey in bytes.
func ExportCredDefPubKey(kh *keyset.Handle) ([]byte, error) {
	buf := new(bytes.Buffer)
	writer := newWriter(buf)

	err := kh.WriteWithNoSecrets(writer)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type writer struct {
	buf *bytes.Buffer
}

func newWriter(buf *bytes.Buffer) *writer {
	return &writer{buf: buf}
}

func (p *writer) Write(ks *tinkpb.Keyset) error {
	keys := ks.Key
	for _, key := range keys {
		if key.KeyId != ks.PrimaryKeyId || key.Status != tinkpb.KeyStatusType_ENABLED {
			continue
		}

		pubKeyProto := new(clproto.CLCredDefPublicKey)

		err := proto.Unmarshal(key.KeyData.Value, pubKeyProto)
		if err != nil {
			return err
		}

		marshaled := make([]byte, len(pubKeyProto.KeyValue))
		copy(marshaled, pubKeyProto.KeyValue)
		p.buf.Write(marshaled)
	}

	return nil
}

func (p *writer) WriteEncrypted(ks *tinkpb.EncryptedKeyset) error {
	return fmt.Errorf("write encrypted function not supported")
}
