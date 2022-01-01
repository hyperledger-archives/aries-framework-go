/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofbandv2_test

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher/outbound"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/anoncrypt"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/authcrypt"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	mockdidcomm "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
)

func TestIntegration(t *testing.T) {
	storeProv := mockstore.NewMockStoreProvider()

	ariesOpts := []aries.Option{
		aries.WithStoreProvider(storeProv),
		aries.WithOutboundTransports(&mockdidcomm.MockOutboundTransport{
			ExpectedResponse: "foo",
			AcceptValue:      true,
		}),
		aries.WithMediaTypeProfiles([]string{transport.MediaTypeDIDCommV2Profile}),
		aries.WithPacker(
			func(prov packer.Provider) (packer.Packer, error) {
				return authcrypt.New(prov, jose.A256CBCHS512)
			},
			func(prov packer.Provider) (packer.Packer, error) {
				return anoncrypt.New(prov, jose.A256GCM)
			},
		),
	}

	agent1, err := aries.New(ariesOpts...)
	require.NoError(t, err)

	ctx1, err := agent1.Context()
	require.NoError(t, err)

	oobSvc1, err := outofbandv2.New(ctx1)
	require.NoError(t, err)

	vdr1 := ctx1.VDRegistry()

	// create other agent's "peer" DID, and save it to primary agent's VDR
	docSave := getOOBV2PeerDoc(t)

	// which we then save to agent1's vdr
	_, err = vdr1.Create("peer", docSave, vdrapi.WithOption("store", true))
	require.NoError(t, err)

	connID, err := oobSvc1.AcceptInvitation(&outofbandv2.Invitation{
		ID:   uuid.New().String(),
		Type: outofbandv2.InvitationMsgType,
		From: docSave.ID,
		Body: &outofbandv2.InvitationBody{},
	})
	require.NoError(t, err)

	lookup := ctx1.ConnectionLookup()

	connRec, err := lookup.GetConnectionRecord(connID)
	require.NoError(t, err)

	outbound1, err := outbound.NewOutbound(ctx1)
	require.NoError(t, err)

	msg := service.NewDIDCommMsgMap(presentproof.ProposePresentationV3{
		ID:          uuid.New().String(),
		Type:        presentproof.ProposePresentationMsgTypeV3,
		Body:        presentproof.ProposePresentationV3Body{},
		Attachments: nil,
	})

	err = outbound1.SendToDID(msg, connRec.MyDID, connRec.TheirDID)
	require.NoError(t, err)
}

func getOOBV2PeerDoc(t *testing.T) *did.Doc {
	t.Helper()

	var (
		peerVDR vdrapi.VDR
		docSave *did.Doc
	)

	agent, err := aries.New(
		aries.WithStoreProvider(mockstore.NewMockStoreProvider()),
		aries.WithMediaTypeProfiles([]string{transport.MediaTypeDIDCommV2Profile}),
		aries.WithVDR(&mockvdr.MockVDR{
			AcceptValue: true,
			StoreErr:    nil,
			ReadFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				didVal, err := did.Parse(didID)
				if err != nil {
					return nil, fmt.Errorf("dummy VDR: %w", err)
				}

				return &did.DocResolution{
					DIDDocument: mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, didVal.MethodSpecificID),
				}, nil
			},
			CreateFunc: func(doc *did.Doc, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				res, err := peerVDR.Create(doc, opts...)
				if err != nil {
					return nil, err
				}

				docSave = res.DIDDocument

				return res, nil
			},
			UpdateFunc:     nil,
			DeactivateFunc: nil,
			CloseErr:       nil,
		}),
	)
	require.NoError(t, err)

	ctx, err := agent.Context()
	require.NoError(t, err)

	peerVDR, err = peer.New(ctx.StorageProvider())
	require.NoError(t, err)

	oobSvc, err := outofbandv2.New(ctx)
	require.NoError(t, err)

	_, err = oobSvc.AcceptInvitation(&outofbandv2.Invitation{
		ID:   uuid.New().String(),
		Type: outofbandv2.InvitationMsgType,
		From: "did:peer:dummyDID",
		Body: &outofbandv2.InvitationBody{},
	})
	require.NoError(t, err)

	require.NotNil(t, docSave)

	return docSave
}
