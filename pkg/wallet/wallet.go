/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/nacl/box"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/crypto/jwe/authcrypt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	didFormat    = "did:%s:%s"
	didPKID      = "%s#keys-%d"
	didServiceID = "%s#endpoint-%d"
)

// provider contains dependencies for the base wallet and is typically created by using aries.Context()
type provider interface {
	StorageProvider() storage.Provider
	InboundTransportEndpoint() string
}

// BaseWallet wallet implementation
type BaseWallet struct {
	store                    storage.Store
	crypter                  crypto.Crypter
	inboundTransportEndpoint string
}

// New return new instance of wallet implementation
func New(ctx provider) (*BaseWallet, error) {
	crypter, err := authcrypt.New(authcrypt.XC20P)
	if err != nil {
		return nil, fmt.Errorf("new authcrypt failed: %w", err)
	}

	store, err := ctx.StorageProvider().GetStoreHandle()
	if err != nil {
		return nil, fmt.Errorf("failed to GetStoreHandle: %w", err)
	}

	return &BaseWallet{store: store, crypter: crypter, inboundTransportEndpoint: ctx.InboundTransportEndpoint()}, nil
}

// CreateEncryptionKey create a new public/private encryption keypair.
func (w *BaseWallet) CreateEncryptionKey() (string, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to GenerateKey: %w", err)
	}
	base58Pub := base58.Encode(pub[:])
	// TODO - need to encrypt the priv before putting them in the store.
	if err := w.persistKey(base58Pub, &crypto.KeyPair{Pub: pub[:], Priv: priv[:]}); err != nil {
		return "", err
	}
	return base58Pub, nil
}

// CreateSigningKey create a new public/private signing keypair.
func (w *BaseWallet) CreateSigningKey() (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to GenerateKey: %w", err)
	}
	base58Pub := base58.Encode(pub[:])
	// TODO - need to encrypt the priv before putting them in the store.
	if err := w.persistKey(base58Pub, &crypto.KeyPair{Pub: pub[:], Priv: priv[:]}); err != nil {
		return "", err
	}
	return base58Pub, nil
}

// SignMessage sign a message using the private key associated with a given verification key.
func (w *BaseWallet) SignMessage(message []byte, fromVerKey string) ([]byte, error) {
	keyPair, err := w.getKey(fromVerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}
	return ed25519signature2018.New().Sign(keyPair.Priv, message)
}

// DecryptMessage decrypt message
func (w *BaseWallet) DecryptMessage(encMessage []byte, toVerKey string) ([]byte, string, error) {
	return nil, "", fmt.Errorf("not implemented")
}

// PackMessage Pack a message for one or more recipients.
func (w *BaseWallet) PackMessage(envelope *Envelope) ([]byte, error) {
	if envelope == nil {
		return nil, errors.New("envelope argument is nil")
	}
	// get keypair from db
	senderKeyPair, err := w.getKey(envelope.FromVerKey)
	if err != nil {
		return nil, fmt.Errorf("failed from getKey: %w", err)
	}

	var recipients [][]byte
	for _, verKey := range envelope.ToVerKeys {
		// TODO It is possible to have different key schemes in an interop situation
		// there is no guarantee that each recipient is using the same key types
		// decode base58 ver key
		verKeyBytes := base58.Decode(verKey)
		// create 32 byte key
		recipients = append(recipients, verKeyBytes)
	}
	// encrypt message
	bytes, err := w.crypter.Encrypt(envelope.Message, *senderKeyPair, recipients)
	if err != nil {
		return nil, fmt.Errorf("failed from encrypt: %w", err)
	}
	return bytes, nil
}

// UnpackMessage Unpack a message.
func (w *BaseWallet) UnpackMessage(encMessage []byte) (*Envelope, error) {
	var e authcrypt.Envelope
	if err := json.Unmarshal(encMessage, &e); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encMessage: %w", err)
	}
	var keysNotFound []string
	for _, v := range e.Recipients {
		recipVKeyB58 := v.Header.KID
		// get keypair from db
		recipientKeyPair, err := w.getKey(recipVKeyB58)
		if err != nil {
			if errors.Is(err, ErrKeyNotFound) {
				keysNotFound = append(keysNotFound, recipVKeyB58)
				continue
			}
			return nil, fmt.Errorf("failed from getKey: %w", err)
		}
		bytes, err := w.crypter.Decrypt(encMessage, *recipientKeyPair)
		if err != nil {
			return nil, fmt.Errorf("failed from decrypt: %w", err)
		}
		return &Envelope{Message: bytes}, nil
	}
	return nil, fmt.Errorf("no corresponding recipient key found in {%s}", keysNotFound)
}

// Close wallet
func (w *BaseWallet) Close() error {
	return nil
}

// CreateDID returns new DID Document
// TODO write the DID Doc to the chosen DID method.
// TODO remove lint when encryption key gets removed from function
func (w *BaseWallet) CreateDID(method string, opts ...DocOpts) (*did.Doc, error) { //nolint:funlen
	docOpts := &createDIDOpts{}
	// Apply options
	for _, opt := range opts {
		opt(docOpts)
	}

	// TODO: remove generate key pair for encryption (there is no key type in DID Spec for this one)
	// It seems that we only need one signing key in DID Doc and that we can
	// generate encryption key from that signing key when we need it
	pubEncryption, err := w.CreateEncryptionKey()
	if err != nil {
		return nil, fmt.Errorf("failed to create DID: %w", err)
	}

	// DID identifier
	id := fmt.Sprintf(didFormat, method, pubEncryption[:16])

	pubKeyEncryption := did.PublicKey{
		ID:         fmt.Sprintf(didPKID, id, 1),
		Type:       "Curve25519",
		Controller: id,
		Value:      []byte(pubEncryption),
	}

	// Generate key pair for signing
	pubSigning, err := w.CreateSigningKey()
	if err != nil {
		return nil, fmt.Errorf("failed to create DID: %w", err)
	}

	pubKeySigning := did.PublicKey{
		ID: fmt.Sprintf(didPKID, id, 2),
		// TODO hardcoding public key type for now
		// Should be dynamic for multi-key support
		Type:       "Ed25519VerificationKey2018",
		Controller: id,
		Value:      []byte(pubSigning),
	}

	// Service model to be included only if service type is provided through opts
	var service []did.Service
	if docOpts.serviceType != "" {
		// Service endpoints
		service = []did.Service{
			{
				ID:              fmt.Sprintf(didServiceID, id, 1),
				Type:            docOpts.serviceType,
				ServiceEndpoint: w.inboundTransportEndpoint,
			},
		}
	}

	// Created time
	createdTime := time.Now()

	doc := &did.Doc{
		Context:   []string{did.Context},
		ID:        id,
		PublicKey: []did.PublicKey{pubKeyEncryption, pubKeySigning},
		Service:   service,
		Created:   &createdTime,
		Updated:   &createdTime,
	}

	// TODO: Resolve signature type based on key type
	signingContext := &signer.Context{
		SignatureType: "Ed25519Signature2018",
		Creator:       pubKeySigning.ID,
		Signer:        newSigner(pubSigning, w),
	}

	return signDocument(signingContext, doc)
}

func newSigner(keyID string, wallet Crypto) *didSigner {
	return &didSigner{keyID: keyID, wallet: wallet}
}

type didSigner struct {
	keyID  string
	wallet Crypto
}

func (s *didSigner) Sign(doc []byte) ([]byte, error) {
	return s.wallet.SignMessage(doc, s.keyID)
}

func signDocument(context *signer.Context, doc *did.Doc) (*did.Doc, error) {
	docBytes, err := doc.JSONBytes()
	if err != nil {
		return nil, err
	}

	signedDocBytes, err := signer.New().Sign(context, docBytes)
	if err != nil {
		return nil, err
	}

	return did.ParseDocument(signedDocBytes)
}

// persistKey save key in storage
func (w *BaseWallet) persistKey(key string, value *crypto.KeyPair) error {
	bytes, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}
	err = w.store.Put(key, bytes)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}
	return nil
}

// getKey get key
func (w *BaseWallet) getKey(verkey string) (*crypto.KeyPair, error) {
	bytes, err := w.store.Get(verkey)
	if err != nil {
		if errors.Is(storage.ErrDataNotFound, err) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	var key crypto.KeyPair
	if err := json.Unmarshal(bytes, &key); err != nil {
		return nil, fmt.Errorf("failed unmarshal to key struct: %w", err)
	}
	return &key, nil
}
