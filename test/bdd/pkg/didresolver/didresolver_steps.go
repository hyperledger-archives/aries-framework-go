/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didresolver

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	bddctx "github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/sidetree"
)

const (
	maxRetry    = 10
	sideTreeURL = "${SIDETREE_URL}"
)

var logger = log.New("aries-framework/didresolver-tests")

// Steps for DID resolver tests.
type Steps struct {
	bddContext *bddctx.BDDContext
}

// NewDIDResolverSteps returns new steps for DID resolver tests.
func NewDIDResolverSteps() *Steps {
	return &Steps{}
}

// SetContext is called before every scenario is run with a fresh new context.
func (d *Steps) SetContext(ctx *bddctx.BDDContext) {
	d.bddContext = ctx
}

func (d *Steps) createDIDDocument(agents, method string) error {
	return createDIDDocument(d.bddContext, agents, "")
}

// CreateDIDDocument creates DIDDocument.
func CreateDIDDocument(ctx *bddctx.BDDContext, agents, keyType string) error {
	return createDIDDocument(ctx, agents, keyType)
}

//nolint:funlen,gocognit,gocyclo
func createDIDDocument(ctx *bddctx.BDDContext, agents, keyType string) error {
	for _, agentID := range strings.Split(agents, ",") {
		signingKT := ctx.AgentCtx[agentID].KeyType()

		if string(signingKT) == "" {
			signingKT = kms.ED25519Type
		}

		encKT := ctx.AgentCtx[agentID].KeyAgreementType()

		if string(signingKT) == "" {
			encKT = kms.X25519ECDHKWType
		}

		pubKeyJWK, ok := ctx.PublicKeys[agentID]
		if !ok {
			_, pubKeyBytes, err := ctx.AgentCtx[agentID].KMS().CreateAndExportPubKeyBytes(signingKT)
			if err != nil {
				return err
			}

			pubKeyJWK, err = jwksupport.JWKFromKey(ed25519.PublicKey(pubKeyBytes))
			if err != nil {
				return err
			}
		}

		_, pubKeyUpdateBytes, err := ctx.AgentCtx[agentID].KMS().CreateAndExportPubKeyBytes(signingKT)
		if err != nil {
			return err
		}

		updateJWK, err := jwksupport.JWKFromKey(ed25519.PublicKey(pubKeyUpdateBytes))
		if err != nil {
			return err
		}

		_, pubKeyRecoveryBytes, err := ctx.AgentCtx[agentID].KMS().CreateAndExportPubKeyBytes(signingKT)
		if err != nil {
			return err
		}

		recoveryJWK, err := jwksupport.JWKFromKey(ed25519.PublicKey(pubKeyRecoveryBytes))
		if err != nil {
			return err
		}

		encKey, ok := ctx.PublicEncKeys[agentID]
		if !ok {
			_, encKey, err = ctx.AgentCtx[agentID].KMS().CreateAndExportPubKeyBytes(encKT)
			if err != nil {
				return err
			}
		}

		serviceType := vdrapi.DIDCommServiceType
		mtps := ctx.AgentCtx[agentID].MediaTypeProfiles()

		for _, mtp := range mtps {
			var found bool

			switch mtp {
			case transport.MediaTypeDIDCommV2Profile, transport.MediaTypeAIP2RFC0587Profile:
				found = true
				serviceType = vdrapi.DIDCommV2ServiceType
			}

			if found {
				break
			}
		}

		doc, err := sidetree.CreateDID(
			&sidetree.CreateDIDParams{
				URL:             ctx.Args[sideTreeURL] + "operations",
				KeyID:           "key1",
				JWK:             pubKeyJWK,
				UpdateJWK:       updateJWK,
				RecoveryJWK:     recoveryJWK,
				EncryptionKey:   encKey,
				KeyType:         keyType,
				EncKeyType:      encKT,
				ServiceEndpoint: ctx.AgentCtx[agentID].ServiceEndpoint(),
				ServiceType:     serviceType,
			})
		if err != nil {
			return err
		}

		ctx.PublicDIDDocs[agentID] = doc
		ctx.PublicDIDs[agentID] = doc.ID
	}

	return nil
}

func (d *Steps) resolveDID(agentID string) error {
	doc, err := resolveDID(d.bddContext.AgentCtx[agentID].VDRegistry(),
		d.bddContext.PublicDIDDocs[agentID].ID, maxRetry)
	if err != nil {
		return err
	}

	if doc == nil {
		return fmt.Errorf("resolved did ID %s is nil", d.bddContext.PublicDIDDocs[agentID].ID)
	}

	return nil
}

func resolveDID(vdr vdrapi.Registry, did string, maxRetry int) (*diddoc.Doc, error) {
	var doc *diddoc.DocResolution

	var err error
	for i := 1; i <= maxRetry; i++ {
		doc, err = vdr.Resolve(did)
		if err == nil || !errors.Is(err, vdrapi.ErrNotFound) {
			return doc.DIDDocument, err
		}

		time.Sleep(1 * time.Second)
		logger.Debugf("Waiting for public did to be published in sidtree: %d second(s)\n", i)
	}

	return doc.DIDDocument, err
}

// RegisterSteps registers did exchange steps.
func (d *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^"([^"]*)" creates public DID for did method "([^"]*)"`, d.createDIDDocument)
	s.Step(`^"([^"]*)" agent successfully resolves DID document$`, d.resolveDID)
}
