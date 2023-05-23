/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdr_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/kmsdidkey"
	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/component/models/did/endpoint"
	ldtestutil "github.com/hyperledger/aries-framework-go/component/models/ld/testutil"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/ed25519signature2018"
	sigutil "github.com/hyperledger/aries-framework-go/component/models/signature/util"
	afgotime "github.com/hyperledger/aries-framework-go/component/models/util/time"
	"github.com/hyperledger/aries-framework-go/component/models/verifiable"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/component/vdr"
	"github.com/hyperledger/aries-framework-go/component/vdr/peer"
	"github.com/hyperledger/aries-framework-go/spi/crypto"
	"github.com/hyperledger/aries-framework-go/spi/kms"
	vdrspi "github.com/hyperledger/aries-framework-go/spi/vdr"

	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	context "github.com/hyperledger/aries-framework-go/pkg/framework/context"
)

func Test_LDProofs_Compatibility(t *testing.T) {
	t.Run("did:peer", func(t *testing.T) {
		alice := agent(t)
		alicePeerDID := createPeerDIDLikeDIDExchangeService(t, alice)
		require.NotEmpty(t, alicePeerDID.Authentication)

		verKey := alicePeerDID.Authentication[0].VerificationMethod
		require.NotNil(t, verKey)

		// alice self-issues a VC
		expectedVC := universityDegreeVC()

		now := time.Now()

		aliceSigner := newCryptoSigner(t, verKey.ID[1:], alice.KMS(), alice.Crypto())

		err := expectedVC.AddLinkedDataProof(
			&verifiable.LinkedDataProofContext{
				SignatureType:           ed25519signature2018.SignatureType,
				Suite:                   ed25519signature2018.New(suite.WithSigner(aliceSigner)),
				SignatureRepresentation: verifiable.SignatureJWS,
				Created:                 &now,
				VerificationMethod:      fmt.Sprintf("%s%s", alicePeerDID.ID, verKey.ID),
				Challenge:               uuid.New().String(),
				Domain:                  uuid.New().String(),
				Purpose:                 "authentication",
			},
			ldtestutil.WithDocumentLoader(t),
		)
		require.NoError(t, err)

		// alice encloses her VC in a VP
		expectedVP, err := verifiable.NewPresentation(verifiable.WithCredentials(expectedVC))
		require.NoError(t, err)

		err = expectedVP.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
			SignatureType:           ed25519signature2018.SignatureType,
			Suite:                   ed25519signature2018.New(suite.WithSigner(aliceSigner)),
			SignatureRepresentation: verifiable.SignatureJWS,
			Created:                 &now,
			VerificationMethod:      fmt.Sprintf("%s%s", alicePeerDID.ID, verKey.ID),
			Challenge:               uuid.New().String(),
			Domain:                  uuid.New().String(),
			Purpose:                 "authentication",
		}, ldtestutil.WithDocumentLoader(t))
		require.NoError(t, err)

		// alice wires her VP and DID to Bob
		aliceVPBits, err := json.Marshal(expectedVP)
		require.NoError(t, err)

		alicePeerDIDBits, err := alicePeerDID.JSONBytes()
		require.NoError(t, err)

		bob := agent(t)

		// bob parses and stores alice's DID
		actualPeerDID, err := did.ParseDocument(alicePeerDIDBits)
		require.NoError(t, err)

		didMethod, err := vdr.GetDidMethod(actualPeerDID.ID)
		require.NoError(t, err)

		_, err = bob.VDRegistry().Create(didMethod, actualPeerDID, vdrspi.WithOption("store", true))
		require.NoError(t, err)

		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		// bob parses alice's VP
		actualVP, err := verifiable.ParsePresentation(
			aliceVPBits,
			verifiable.WithPresPublicKeyFetcher(verifiable.NewVDRKeyResolver(bob.VDRegistry()).PublicKeyFetcher()),
			verifiable.WithPresJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		require.Equal(t, expectedVP.Context, actualVP.Context)
		require.Equal(t, expectedVP.Type, actualVP.Type)

		actualVCBits, err := actualVP.MarshalledCredentials()
		require.NoError(t, err)
		require.Len(t, actualVCBits, 1)

		// bob parses the VCs enclosed in alice's VP
		actualVC, err := verifiable.ParseCredential(
			actualVCBits[0],
			verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(bob.VDRegistry()).PublicKeyFetcher()),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		require.Equal(t, expectedVC.Context, actualVC.Context)
		require.Equal(t, expectedVC.Types, actualVC.Types)
	})
}

func agent(t *testing.T) *context.Provider {
	t.Helper()

	a, err := aries.New(
		aries.WithStoreProvider(mem.NewProvider()),
		aries.WithProtocolStateStoreProvider(mem.NewProvider()),
	)
	require.NoError(t, err)

	ctx, err := a.Context()
	require.NoError(t, err)

	return ctx
}

func createPeerDIDLikeDIDExchangeService(t *testing.T, a *context.Provider) *did.Doc {
	t.Helper()

	authVM := getSigningKey(t, a)

	docResolution, err := a.VDRegistry().Create(
		peer.DIDMethod, &did.Doc{
			Service: []did.Service{
				{
					ServiceEndpoint: endpoint.NewDIDCommV1Endpoint("http://example.com/didcomm"),
					Type:            "did-communication",
				},
			},
			VerificationMethod: []did.VerificationMethod{
				authVM,
			},
			KeyAgreement: []did.Verification{
				{
					VerificationMethod: newKeyAgreementVM(t, a, authVM.Controller),
					Relationship:       did.KeyAgreement,
				},
			},
		},
	)
	require.NoError(t, err)

	strJ := formatDoc(t, docResolution.DIDDocument)

	t.Log("DID Doc created: ***\n" + strJ + "\n***")

	return docResolution.DIDDocument
}

func newKeyAgreementVM(t *testing.T, p *context.Provider, controller string) did.VerificationMethod {
	t.Helper()

	_, encPubKey, err := p.KMS().CreateAndExportPubKeyBytes(p.KeyAgreementType())
	require.NoError(t, err)

	encDIDKey, err := kmsdidkey.BuildDIDKeyByKeyType(encPubKey, p.KeyAgreementType())
	require.NoError(t, err)

	const didPKID = "%s#keys-%d"

	encPubKeyID := fmt.Sprintf(didPKID, controller, 2)

	return did.VerificationMethod{
		ID:         encPubKeyID,
		Type:       "X25519KeyAgreementKey2019",
		Controller: controller,
		Value:      []byte(encDIDKey),
	}
}

func getSigningKey(t *testing.T, a *context.Provider) did.VerificationMethod {
	const (
		didFormat = "did:%s:%s"
		method    = "test"
	)

	keyID, pubBytes, err := a.KMS().CreateAndExportPubKeyBytes(a.KeyType())
	require.NoError(t, err)

	didKey, err := kmsdidkey.BuildDIDKeyByKeyType(pubBytes, a.KeyType())
	require.NoError(t, err)

	id := fmt.Sprintf(didFormat, method, didKey[:16])

	return did.VerificationMethod{ID: "#" + keyID, Controller: id, Value: pubBytes, Type: "Ed25519VerificationKey2018"}
}

func formatDoc(t *testing.T, d *did.Doc) string {
	bits, err := d.JSONBytes()
	require.NoError(t, err)

	var buf bytes.Buffer

	err = json.Indent(&buf, bits, "", "\t")
	require.NoError(t, err)

	return buf.String()
}

func universityDegreeVC() *verifiable.Credential {
	return &verifiable.Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
		},
		Types: []string{
			"VerifiableCredential",
			"UniversityDegreeCredential",
		},
		ID: "http://example.gov/credentials/ff98f978-588f-4eb0-b17b-60c18e1dac2c",
		Issuer: verifiable.Issuer{
			ID: "did:web:vc.transmute.world",
			CustomFields: map[string]interface{}{
				"name": "Transmute University",
			},
		},
		Issued: &afgotime.TimeWrapper{Time: time.Now()},
		Subject: &verifiable.Subject{
			ID: "did:example:ebfeb1f712ebc6f1c276e12ec21",
			CustomFields: map[string]interface{}{
				"degree": map[string]string{
					"type":   "BachelorDegree",
					"degree": "MIT",
				},
				"name":   "Jayden Doe",
				"spouse": "Bob Doe",
			},
		},
	}
}

func newCryptoSigner(t *testing.T, kid string, agentKMS kms.KeyManager,
	agentCrypto crypto.Crypto) sigutil.Signer {
	t.Helper()

	kh, err := agentKMS.Get(kid)
	require.NoError(t, err)

	return &cryptoSigner{
		cr: agentCrypto,
		kh: kh,
	}
}

type cryptoSigner struct {
	PubKeyBytes []byte
	PubKey      interface{}

	cr crypto.Crypto
	kh interface{}
}

// Sign will sign document and return signature.
func (s *cryptoSigner) Sign(msg []byte) ([]byte, error) {
	return s.cr.Sign(msg, s.kh)
}

// Alg return alg.
func (s *cryptoSigner) Alg() string {
	return ""
}

// VerificationMethod returns a public key object (e.g. ed25519.VerificationMethod or *ecdsa.PublicKey).
func (s *cryptoSigner) PublicKey() interface{} {
	return s.PubKey
}

// PublicKeyBytes returns bytes of the public key.
func (s *cryptoSigner) PublicKeyBytes() []byte {
	return s.PubKeyBytes
}
