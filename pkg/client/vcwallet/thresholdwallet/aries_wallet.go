package thresholdwallet

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/client/vcwallet"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	bls12381 "github.com/kilic/bls12-381"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	thwallet "github.com/perun-network/bbs-plus-threshold-wallet/wallet"
	"github.com/piprate/json-gold/ld"
	"golang.org/x/exp/slices"
)

const (
	walletExpiry = 10 * time.Minute
)

// provider contains dependencies for the verifiable credential wallet client
// and is typically created by using aries.Context().
type provider interface {
	StorageProvider() storage.Provider
	VDRegistry() vdr.Registry
	Crypto() crypto.Crypto
	JSONLDDocumentLoader() ld.DocumentLoader
	MediaTypeProfiles() []string
	didCommProvider // to be used only if wallet needs to be participated in DIDComm.
}

// didCommProvider to be used only if wallet needs to be participated in DIDComm operation.
// TODO: using wallet KMS instead of provider KMS.
// TODO: reconcile Protocol storage with wallet store.
type didCommProvider interface {
	KMS() kms.KeyManager
	ServiceEndpoint() string
	ProtocolStateStorageProvider() storage.Provider
	Service(id string) (interface{}, error)
	KeyType() kms.KeyType
	KeyAgreementType() kms.KeyType
}

type Client struct {
	userID        string
	vcwallet      *vcwallet.Client
	isExpired     bool
	collectionIDs []string
}

func New(userID string, ctx provider, options ...wallet.UnlockOptions) (*Client, error) {
	vcwallet, err := vcwallet.New(userID, ctx, options...)
	if err != nil {
		return nil, err
	}
	return &Client{
		userID:        userID,
		vcwallet:      vcwallet,
		isExpired:     true,
		collectionIDs: make([]string, 0),
	}, nil
}

// CreateProfile creates a new verifiable credential wallet profile for given user.
// returns error if wallet profile is already created.
// Use `UpdateProfile()` for replacing an already created verifiable credential wallet profile.
func CreateProfile(userID string, ctx provider, options ...wallet.ProfileOptions) error {
	return wallet.CreateProfile(userID, ctx, options...)
}

// UpdateProfile updates existing verifiable credential wallet profile.
// Will create new profile if no profile exists for given user.
// Caution: you might lose your existing keys if you change kms options.
func UpdateProfile(userID string, ctx provider, options ...wallet.ProfileOptions) error {
	return wallet.UpdateProfile(userID, ctx, options...)
}

// ProfileExists checks if profile exists for given wallet user, returns error if not found.
func ProfileExists(userID string, ctx provider) error {
	return wallet.ProfileExists(userID, ctx)
}

func (c *Client) Open() error {
	if err := c.vcwallet.Open(wallet.WithUnlockExpiry(walletExpiry)); err != nil {
		return err
	}
	c.isExpired = false
	c.watchExpiry()
	return nil
}

func (c *Client) Close() error {
	if !c.isExpired {
		c.vcwallet.Close()
		c.isExpired = true
	}
	return nil
}

func (c *Client) Store(document *thwallet.Document) error {
	// Check if the document's collection is already stored.
	if !slices.Contains(c.collectionIDs, document.CollectionID) {
		collection := newCollection(document.CollectionID, c.userID)
		collectionBytes, err := json.Marshal(collection)
		if err != nil {
			return fmt.Errorf("marshal collection: %w", err)
		}
		err = c.vcwallet.Add(wallet.Collection, collectionBytes)
		if err != nil {
			return fmt.Errorf("add a new collection to wallet: %w", err)
		}
		c.collectionIDs = append(c.collectionIDs, collection.ID)
	}

	// Store document based on its type.
	switch document.Type {
	case thwallet.Credential:
		cred, err := newCredential(document)
		if err != nil {
			return fmt.Errorf("create credential: %w", err)
		}
		credBytes, err := cred.MarshalJSON()
		if err != nil {
			return fmt.Errorf("marshal credential: %w", err)
		}
		err = c.vcwallet.Add(wallet.Credential,
			credBytes,
			wallet.AddByCollection(document.CollectionID))
		if err != nil {
			return fmt.Errorf("add new credential to wallet: %w", err)
		}
	case thwallet.Signature, thwallet.Presignature, thwallet.PartialSignature, thwallet.SecretKey, thwallet.PublicKey:
		metadata, err := newMetadata(document)
		if err != nil {
			return fmt.Errorf("create signature: %w", err)
		}
		metadataBytes, err := json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("marshal signature: %w", err)
		}
		err = c.vcwallet.Add(wallet.Metadata,
			metadataBytes,
			wallet.AddByCollection(document.CollectionID))
		if err != nil {
			return fmt.Errorf("add metadata to collection: %w", err)
		}
	default:
		return errors.New("unknown document type")
	}
	return nil
}

func (c *Client) AddCollection(collectionID string) error {
	collection := newCollection(collectionID, c.userID)
	collectionBytes, err := json.Marshal(collection)
	if err != nil {
		return fmt.Errorf("marshal collection: %w", err)
	}
	err = c.vcwallet.Add(wallet.Collection, collectionBytes)
	if err != nil {
		return fmt.Errorf("add a new collection to wallet: %w", err)
	}
	c.collectionIDs = append(c.collectionIDs, collection.ID)
	return nil
}

func (c *Client) Get(contentType thwallet.ContentType, documentID string) (*thwallet.Document, error) {
	switch contentType {
	case thwallet.Credential:
		credentialBytes, err := c.vcwallet.Get(wallet.Credential, documentID)
		if err != nil {
			return nil, err
		}
		var credential verifiable.Credential
		err = json.Unmarshal(credentialBytes, &credential)
		if err != nil {
			return nil, fmt.Errorf("unmarshal credential bytes: %w", err)
		}
		document, err := documentFromSubject(credential.Subject)
		if err != nil {
			return nil, fmt.Errorf("retrieve document from credential: %w", err)
		}
		if document.Type == thwallet.Credential {
			return document, nil
		}
		return nil, errors.New("document has wrong type")
	case thwallet.Signature, thwallet.Presignature, thwallet.PartialSignature, thwallet.PublicKey, thwallet.SecretKey:
		metadataBytes, err := c.vcwallet.Get(wallet.Metadata, documentID)
		if err != nil {
			return nil, err
		}
		var metadata ThresholdWalletMetaData
		err = json.Unmarshal(metadataBytes, &metadata)
		if err != nil {
			return nil, fmt.Errorf("unmarshal metadata  bytes: %w", err)
		}
		document := metadata.Subject
		if document.Type == contentType {
			return document, nil
		}
		return nil, errors.New("document has wrong type")

	default:
		return nil, errors.New("unsupported document type")
	}
}

func (c *Client) GetCollection(collectionID string) ([]*thwallet.Document, error) {
	var collection []*thwallet.Document

	// Get all credentials from the collection.
	credentials, err := c.vcwallet.GetAll(wallet.Credential, wallet.FilterByCollection(collectionID+collectionID))
	if err != nil {
		return nil, fmt.Errorf("get credentials with collection id %s: %w", collectionID, err)
	}
	for key, value := range credentials {
		var credential verifiable.Credential
		err := json.Unmarshal(value, &credential)
		if err != nil {
			return nil, fmt.Errorf("unmarshal credential %s: %w", key, err)
		}
		document, err := documentFromSubject(credential.Subject)
		if err != nil {
			return nil, fmt.Errorf("retrieve document from credential: %w", err)
		}
		collection = append(collection, document)
	}

	// Get all metadatas from the collection
	metadatas, err := c.vcwallet.GetAll(wallet.Metadata, wallet.FilterByCollection(collectionID))
	if err != nil {
		return nil, fmt.Errorf("get signatures with collection id %s: %w", collectionID, err)
	}
	for key, value := range metadatas {
		var metadata ThresholdWalletMetaData
		err := json.Unmarshal(value, &metadata)
		if err != nil {
			return nil, fmt.Errorf("unmarshal metadata %s: %w", key, err)
		}

		document := metadata.Subject
		collection = append(collection, document)
	}
	return collection, nil
}

func (c *Client) Remove(contentType thwallet.ContentType, documentID string) error {
	switch contentType {
	case thwallet.Credential:
		err := c.vcwallet.Remove(wallet.Credential, documentID)
		if err != nil {
			return err
		}
		return nil
	case thwallet.Signature, thwallet.Presignature, thwallet.PartialSignature, thwallet.SecretKey, thwallet.PublicKey:
		err := c.vcwallet.Remove(wallet.Metadata, documentID)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("remove content type not supported")
	}
}

func (c *Client) VerifyThresholdSignature(
	credentials []*thwallet.Document,
	signature *thwallet.Document,
	publicKey *thwallet.Document) (bool, error) {

	if credentials[0] == nil {
		return false, errors.New("empty credentials list")
	}
	var messages []*bls12381.Fr
	collectionID := credentials[0].CollectionID
	for _, credential := range credentials {
		if credential.Type != thwallet.Credential {
			return false, errors.New("unsupported document type")
		}
		if collectionID != credential.CollectionID {
			return false, errors.New("unmatching collection ID")
		}
		message := bls12381.NewFr().FromBytes(credential.Content)
		messages = append(messages, message)
	}
	if signature.Type != thwallet.Signature {
		return false, errors.New("type failed signature")
	}
	if publicKey.Type != thwallet.PublicKey {
		return false, errors.New("type failed public key")
	}

	thresholdSig := fhks_bbs_plus.NewThresholdSignature()
	err := thresholdSig.FromBytes(signature.Content)
	if err != nil {
		return false, fmt.Errorf("decode threshold signature: %w", err)
	}

	pk := &fhks_bbs_plus.PublicKey{}
	err = pk.FromBytes(publicKey.Content)
	if err != nil {
		return false, fmt.Errorf("decode public key: %w", err)
	}

	return thresholdSig.Verify(messages, pk), nil
}

func (c *Client) RemoveCollection(collectionID string) error {
	err := c.vcwallet.Remove(wallet.Collection, collectionID)
	if err != nil {
		return fmt.Errorf("remove collection from wallet: %w", err)
	}
	return nil
}

func (c *Client) watchExpiry() {
	timeout := time.After(walletExpiry)
	expiredSignal := make(chan bool)
	for {
		if c.isExpired {
			expiredSignal <- c.isExpired
		}
		select {
		case <-timeout:
			c.isExpired = true
			log.Print("Wallet expired!")
			return
		case <-expiredSignal:
			log.Print("Wallet is closed.")
			return
		}
	}
}
