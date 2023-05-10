/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	ed25519pb "github.com/google/tink/go/proto/ed25519_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"golang.org/x/crypto/nacl/box"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/localkms/internal/keywrapper"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/util/cryptoutil"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

// TODO: move CryptoBox out of the KMS package.
//   this currently only sits inside LocalKMS so it can access private keys. See issue #511
// TODO delete this file and its corresponding test file when LegacyPacker is removed.

// CryptoBox provides an elliptic-curve-based authenticated encryption scheme
//
// Payloads are encrypted using symmetric encryption (XChacha20Poly1305)
// using a shared key derived from a shared secret created by
//
//	Curve25519 Elliptic Curve Diffie-Hellman key exchange.
//
// CryptoBox is created by a KMS, and reads secret keys from the KMS
//
//	for encryption/decryption, so clients do not need to see
//	the secrets themselves.
type CryptoBox struct {
	km *LocalKMS
}

// NewCryptoBox creates a CryptoBox which provides crypto box encryption using the given KMS's key.
func NewCryptoBox(w kms.KeyManager) (*CryptoBox, error) {
	lkms, ok := w.(*LocalKMS)
	if !ok {
		return nil, fmt.Errorf("cannot use parameter argument as KMS")
	}

	return &CryptoBox{km: lkms}, nil
}

// Easy seals a message with a provided nonce
// theirPub is used as a public key, while myPub is used to identify the private key that should be used.
func (b *CryptoBox) Easy(payload, nonce, theirPub []byte, myKID string) ([]byte, error) {
	var recPubBytes [cryptoutil.Curve25519KeySize]byte

	copy(recPubBytes[:], theirPub)

	senderPriv, err := b.km.exportEncPrivKeyBytes(myKID)
	if err != nil {
		return nil, fmt.Errorf("easy: failed to export sender key: %w, kid: %v", err, myKID)
	}

	var (
		priv       [cryptoutil.Curve25519KeySize]byte
		nonceBytes [cryptoutil.NonceSize]byte
	)

	copy(priv[:], senderPriv)
	copy(nonceBytes[:], nonce)

	ret := box.Seal(nil, payload, &nonceBytes, &recPubBytes, &priv)

	return ret, nil
}

// EasyOpen unseals a message sealed with Easy, where the nonce is provided
// theirPub is the public key used to decrypt directly, while myPub is used to identify the private key to be used.
func (b *CryptoBox) EasyOpen(cipherText, nonce, theirPub, myPub []byte) ([]byte, error) {
	//	 myPub is used to get the recipient private key for decryption
	var sendPubBytes [cryptoutil.Curve25519KeySize]byte

	copy(sendPubBytes[:], theirPub)

	kid, err := jwkkid.CreateKID(myPub, kms.ED25519Type)
	if err != nil {
		return nil, err
	}

	senderPriv, err := b.km.exportEncPrivKeyBytes(kid)
	if err != nil {
		return nil, err
	}

	var (
		priv       [cryptoutil.Curve25519KeySize]byte
		nonceBytes [cryptoutil.NonceSize]byte
	)

	copy(priv[:], senderPriv)
	copy(nonceBytes[:], nonce)

	out, success := box.Open(nil, cipherText, &nonceBytes, &sendPubBytes, &priv)
	if !success {
		return nil, errors.New("failed to unpack")
	}

	return out, nil
}

// Seal seals a payload using the equivalent of libsodium box_seal
//
// Generates an ephemeral keypair to use for the sender, and includes
// the ephemeral sender public key in the message.
func (b *CryptoBox) Seal(payload, theirEncPub []byte, randSource io.Reader) ([]byte, error) {
	// generate ephemeral curve25519 asymmetric keys
	epk, esk, err := box.GenerateKey(randSource)
	if err != nil {
		return nil, err
	}

	var recPubBytes [cryptoutil.Curve25519KeySize]byte

	copy(recPubBytes[:], theirEncPub)

	nonce, err := cryptoutil.Nonce(epk[:], theirEncPub)
	if err != nil {
		return nil, err
	}

	// now seal the msg with the ephemeral key, nonce and recPub (which is recipient's publicKey)
	ret := box.Seal(epk[:], payload, nonce, &recPubBytes, esk)

	return ret, nil
}

// SealOpen decrypts a payload encrypted with Seal
//
// Reads the ephemeral sender public key, prepended to a properly-formatted message,
// and uses that along with the recipient private key corresponding to myPub to decrypt the message.
func (b *CryptoBox) SealOpen(cipherText, myPub []byte) ([]byte, error) {
	if len(cipherText) < cryptoutil.Curve25519KeySize {
		return nil, errors.New("message too short")
	}

	kid, err := jwkkid.CreateKID(myPub, kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("sealOpen: failed to compute ED25519 kid: %w", err)
	}

	recipientEncPriv, err := b.km.exportEncPrivKeyBytes(kid)
	if err != nil {
		return nil, fmt.Errorf("sealOpen: failed to exportPriveKeyBytes: %w", err)
	}

	var (
		epk  [cryptoutil.Curve25519KeySize]byte
		priv [cryptoutil.Curve25519KeySize]byte
	)

	copy(epk[:], cipherText[:cryptoutil.Curve25519KeySize])
	copy(priv[:], recipientEncPriv)

	recEncPub, err := cryptoutil.PublicEd25519toCurve25519(myPub)
	if err != nil {
		return nil, fmt.Errorf("sealOpen: failed to convert pub Ed25519 to X25519 key: %w", err)
	}

	nonce, err := cryptoutil.Nonce(epk[:], recEncPub)
	if err != nil {
		return nil, err
	}

	out, success := box.Open(nil, cipherText[cryptoutil.Curve25519KeySize:], nonce, &epk, &priv)
	if !success {
		return nil, errors.New("failed to unpack")
	}

	return out, nil
}

// exportEncPrivKeyBytes temporary support function for crypto_box to be used with legacyPacker only.
func (l *LocalKMS) exportEncPrivKeyBytes(id string) ([]byte, error) {
	kh, err := l.getKeySet(id)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	bWriter := keyset.NewBinaryWriter(buf)

	kw, err := keywrapper.New(&noop.NoLock{}, "local-lock://tmp")
	if err != nil {
		return nil, err
	}

	primaryKeyEnvAEAD := aead.NewKMSEnvelopeAEAD2(aead.AES256GCMKeyTemplate(), kw)

	err = kh.Write(bWriter, primaryKeyEnvAEAD)
	if err != nil {
		return nil, err
	}

	encryptedKS := &tinkpb.EncryptedKeyset{}

	err = proto.Unmarshal(buf.Bytes(), encryptedKS)
	if err != nil {
		return nil, err
	}

	decryptedKS, err := primaryKeyEnvAEAD.Decrypt(encryptedKS.EncryptedKeyset, []byte{})
	if err != nil {
		return nil, err
	}

	return extractPrivKey(decryptedKS)
}

func extractPrivKey(marshalledKeySet []byte) ([]byte, error) {
	ks := &tinkpb.Keyset{}

	err := proto.Unmarshal(marshalledKeySet, ks)
	if err != nil {
		return nil, err
	}

	for _, key := range ks.Key {
		if key.KeyId != ks.PrimaryKeyId || key.Status != tinkpb.KeyStatusType_ENABLED {
			continue
		}

		prvKey := &ed25519pb.Ed25519PrivateKey{}

		err = proto.Unmarshal(key.KeyData.Value, prvKey)
		if err != nil {
			return nil, err
		}

		pkBytes := make([]byte, ed25519.PrivateKeySize)
		copy(pkBytes[:ed25519.PublicKeySize], prvKey.KeyValue)
		copy(pkBytes[ed25519.PublicKeySize:], prvKey.PublicKey.KeyValue)

		return cryptoutil.SecretEd25519toCurve25519(pkBytes)
	}

	return nil, errors.New("private key not found")
}
