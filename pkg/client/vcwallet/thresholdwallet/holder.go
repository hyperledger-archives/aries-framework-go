package thresholdwallet

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"time"

	jsonld "github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	ldproof "github.com/hyperledger/aries-framework-go/component/models/ld/proof"
	"github.com/hyperledger/aries-framework-go/component/models/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/client/vcwallet"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"golang.org/x/exp/slices"
)

type Holder struct {
	userID        string
	vcwallet      *vcwallet.Client
	context       provider
	collectionIDs []string
	threshold     int
	msgIndex      int
	maxIndex      int
	partySigners  []*PartySigner
}

func NewHolder(userID string, k int, ctx provider, options ...wallet.UnlockOptions) (*Holder, error) {
	vcwallet, err := vcwallet.New(userID, ctx, options...)
	if err != nil {
		return nil, err
	}
	return &Holder{
		userID:        userID,
		vcwallet:      vcwallet,
		context:       ctx,
		collectionIDs: make([]string, 0),
		threshold:     -1,
		maxIndex:      k,
		msgIndex:      0,
		partySigners:  make([]*PartySigner, 0),
	}, nil
}

func (c *Holder) Open(options ...wallet.UnlockOptions) error {
	if err := c.vcwallet.Open(options...); err != nil {
		return err
	}
	return nil
}

func (c *Holder) Close() error {
	c.vcwallet.Close()
	return nil
}

func (c *Holder) Store(document *Document) error {
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
	case Credential:
		cred, err := credentialFromDocument(document)
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
	case Precomputation, PublicKey:
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

func (c *Holder) AddCollection(collectionID string) error {
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

func (c *Holder) Get(contentType ContentType, documentID string, collectionID string) (*Document, error) {
	switch contentType {
	case Credential:
		credentialsBytes, err := c.vcwallet.GetAll(wallet.Credential, wallet.FilterByCollection(collectionID))
		if err != nil {
			return nil, err
		}
		document, err := documentFromCredential(credentialsBytes[documentID], collectionID)
		if err != nil {
			return nil, fmt.Errorf("retrieve document from credential: %w", err)
		}
		return document, nil
	case Precomputation, PublicKey:
		metadatasBytes, err := c.vcwallet.GetAll(wallet.Metadata, wallet.FilterByCollection(collectionID))
		if err != nil {
			return nil, err
		}
		var metadata ThresholdWalletMetaData
		err = json.Unmarshal(metadatasBytes[documentID], &metadata)
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

func (c *Holder) GetCollection(collectionID string) ([]*Document, error) {
	var collection []*Document

	// Get all credentials from the collection.
	credentials, err := c.vcwallet.GetAll(wallet.Credential, wallet.FilterByCollection(collectionID+collectionID))
	if err != nil {
		return nil, fmt.Errorf("get credentials with collection id %s: %w", collectionID, err)
	}
	for _, value := range credentials {
		document, err := documentFromCredential(value, collectionID)
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

func (c *Holder) Remove(contentType ContentType, documentID string) error {
	switch contentType {
	case Credential:
		err := c.vcwallet.Remove(wallet.Credential, documentID)
		if err != nil {
			return err
		}
		return nil
	case Precomputation, PublicKey:
		err := c.vcwallet.Remove(wallet.Metadata, documentID)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("remove content type not supported")
	}
}

func (c *Holder) RemoveCollection(collectionID string) error {
	err := c.vcwallet.Remove(wallet.Collection, collectionID)
	if err != nil {
		return fmt.Errorf("remove collection from wallet: %w", err)
	}
	return nil
}

func (c *Holder) Sign(credential *Document) (*Document, error) {
	vc, err := verifiable.ParseCredential(credential.Content,
		verifiable.WithJSONLDDocumentLoader(c.context.JSONLDDocumentLoader()),
		verifiable.WithCredDisableValidation(),
	)
	if err != nil {
		return nil, err
	}
	created := time.Now()
	indices := generateRandomIndices(c.threshold, len(c.partySigners))
	partialSignatures := make([][]byte, c.threshold)
	for i := 0; i < c.threshold; i++ {
		partialCredential := NewDocument(Credential, credential.Content, credential.CollectionID)
		partialCredential.Indices = indices
		partialCredential.MsgIndex = c.msgIndex
		partialCredential.Created = &created
		partialSignedCredential, err := c.partySigners[indices[i]-1].Sign(partialCredential)
		if err != nil {
			return nil, err
		}

		partialSignedVC, err := verifiable.ParseCredential(partialSignedCredential.Content,
			verifiable.WithJSONLDDocumentLoader(c.context.JSONLDDocumentLoader()),
			verifiable.WithCredDisableValidation(),
			verifiable.WithDisabledProofCheck(),
		)
		if err != nil {
			return nil, err
		}
		partialSignature, err := validatePartialSignature(partialSignedVC.Proofs[0])
		if err != nil {
			return nil, err
		}

		partialSignatures[i] = partialSignature
	}

	thresholdSigner := signer.NewThresholdBBSG2SignatureSigner(c.threshold, credential.MsgIndex, partialSignatures)
	sigSuite := bbsblssignature2020.New(
		suite.WithSigner(thresholdSigner),
		suite.WithVerifier(bbsblssignature2020.NewG2PublicKeyVerifier()))

	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: verifiable.SignatureProofValue,
		Suite:                   sigSuite,
		VerificationMethod:      "did:bbspublickey#key",
		Created:                 &created,
	}

	err = vc.AddLinkedDataProof(ldpContext, jsonld.WithDocumentLoader(c.context.JSONLDDocumentLoader()))
	if err != nil {
		return nil, err
	}

	vcSignedBytes, err := json.Marshal(vc)
	if err != nil {
		return nil, err
	}
	credential.Content = vcSignedBytes
	return credential, nil
}

func (c *Holder) Verify(signedCredential *Document, publicKey *Document) (bool, error) {
	_, err := verifiable.ParseCredential(signedCredential.Content,
		verifiable.WithJSONLDDocumentLoader(c.context.JSONLDDocumentLoader()),
		verifiable.WithPublicKeyFetcher(verifiable.SingleKey(publicKey.Content, "Bls12381G2Key2020")))
	if err != nil {
		return false, fmt.Errorf("credential verification failed: %w", err)
	}
	return true, nil
}

func (c *Holder) AddPartySigner(ps *PartySigner) error {
	if ps == nil {
		return errors.New("nil pointer party signer")
	}
	if c.partySigners == nil {
		c.partySigners = make([]*PartySigner, 0)
	}
	c.partySigners = append(c.partySigners, ps)
	return nil
}

func (c *Holder) RemovePartySigner(psID string) error {
	var newPartySigners []*PartySigner

	for _, party := range c.partySigners {
		if party.userID != psID {
			newPartySigners = append(newPartySigners, party)
		}
	}

	if len(newPartySigners) == len(c.partySigners) {
		return fmt.Errorf("party wallet with ID %s not found", psID)
	}

	c.partySigners = newPartySigners
	return nil
}

func (c *Holder) SetThreshold(threshold int) error {
	if len(c.partySigners) < threshold {
		return errors.New("threshold out of bound")
	}
	c.threshold = threshold
	return nil
}

func (c *Holder) SetNexMsgIndex(nextMsgIndex int) error {
	if nextMsgIndex >= c.maxIndex {
		return errors.New("next message out of bound")
	}
	c.msgIndex = nextMsgIndex
	return nil
}

func generateRandomIndices(threshold, numOfParties int) []int {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	used := make(map[int]bool)

	indices := make([]int, 0)
	for len(indices) < threshold {
		r := rng.Intn(numOfParties) + 1
		if !used[r] {
			used[r] = true
			indices = append(indices, r)
		}
	}
	return indices
}

// validatePartialSignature checks the verifiable proof,
// and returns the actual partial signature if the format is correct.
func validatePartialSignature(proof verifiable.Proof) ([]byte, error) {

	sigType, ok := proof["type"].(string)
	if !ok {
		return nil, errors.New("missing type")
	}
	if sigType != "BbsBlsSignature2020" {
		return nil, errors.New("false signature type")
	}

	verificationMethod, ok := proof["verificationMethod"].(string)
	if !ok {
		return nil, errors.New("missing verfication method")
	}
	if verificationMethod != "did:bbspublickey#key" {
		return nil, errors.New("false verification method")
	}

	proofValue, ok := proof["proofValue"].(string)
	if !ok {
		return nil, errors.New("missing proofValue")
	}

	partialSignatureBytes, err := ldproof.DecodeProofValue(proofValue, "BbsBlsSignature2020")
	if err != nil {
		return nil, err
	}
	return partialSignatureBytes, nil
}
