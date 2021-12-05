/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofbandv2

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	gojose "github.com/square/go-jose/v3"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// Name of this protocol service.
	Name = "out-of-band/2.0"
	// dbName is the name of this service's db stores.
	dbName = "_OutOfBand2"
	// PIURI is the Out-of-Band protocol's protocol instance URI.
	PIURI = "https://didcomm.org/" + Name
	// InvitationMsgType is the '@type' for the invitation message.
	InvitationMsgType = PIURI + "/invitation"

	// TODO channel size - https://github.com/hyperledger/aries-framework-go/issues/246
	callbackChannelSize = 10

	contextKey = "context_%s"

	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
	bls12381G2Key2020          = "Bls12381G2Key2020"
	jsonWebKey2020             = "JsonWebKey2020"
	x25519KeyAgreementKey2019  = "X25519KeyAgreementKey2019"
)

var logger = log.New(fmt.Sprintf("aries-framework/%s/service", Name))

// Service implements the Out-Of-Band V2 protocol.
type Service struct {
	service.Action
	service.Message
	vdrRegistry            vdrapi.Registry
	callbackChannel        chan *callback
	transientStore         storage.Store
	connectionRecorder     *connection.Recorder
	inboundHandler         func() service.InboundHandler
	listenerFunc           func()
	messenger              service.Messenger
	myMediaTypeProfiles    []string
	kms                    kms.KeyManager
	keyType                kms.KeyType
	keyAgreementType       kms.KeyType
	msgTypeServicesTargets map[string]string
	allServices            []dispatcher.ProtocolService
	initialized            bool
}

type callback struct {
	msg service.DIDCommMsg
}

// Provider provides this service's dependencies.
type Provider interface {
	Service(id string) (interface{}, error)
	StorageProvider() storage.Provider
	VDRegistry() vdrapi.Registry
	ProtocolStateStorageProvider() storage.Provider
	InboundDIDCommMessageHandler() func() service.InboundHandler
	Messenger() service.Messenger
	KMS() kms.KeyManager
	KeyType() kms.KeyType
	KeyAgreementType() kms.KeyType
	MediaTypeProfiles() []string
	ServiceMsgTypeTargets() []dispatcher.MessageTypeTarget
	AllServices() []dispatcher.ProtocolService
}

// New creates a new instance of the out-of-band service.
func New(p Provider) (*Service, error) {
	svc := Service{}

	err := svc.Initialize(p)
	if err != nil {
		return nil, err
	}

	return &svc, nil
}

// Initialize initializes the Service. If Initialize succeeds, any further call is a no-op.
func (s *Service) Initialize(prov interface{}) error {
	if s.initialized {
		return nil
	}

	p, ok := prov.(Provider)
	if !ok {
		return fmt.Errorf("oob/2.0 expected provider of type `%T`, got type `%T`", Provider(nil), p)
	}

	store, err := p.ProtocolStateStorageProvider().OpenStore(dbName)
	if err != nil {
		return fmt.Errorf("oob/2.0 failed to open the transientStore : %w", err)
	}

	err = p.ProtocolStateStorageProvider().SetStoreConfig(dbName,
		storage.StoreConfiguration{TagNames: []string{contextKey}})
	if err != nil {
		return fmt.Errorf("oob/2.0 failed to set transientStore config in protocol state transientStore: %w", err)
	}

	msgTypeServicesTargets := map[string]string{}

	for _, v := range p.ServiceMsgTypeTargets() {
		msgTypeServicesTargets[v.Target] = v.MsgType
	}

	connRecorder, err := connection.NewRecorder(p)
	if err != nil {
		return fmt.Errorf("failed to initialize connection recorder: %w", err)
	}

	s.callbackChannel = make(chan *callback, callbackChannelSize)
	s.transientStore = store
	s.vdrRegistry = p.VDRegistry()
	s.connectionRecorder = connRecorder
	s.inboundHandler = p.InboundDIDCommMessageHandler()
	s.messenger = p.Messenger()
	s.myMediaTypeProfiles = p.MediaTypeProfiles()
	s.msgTypeServicesTargets = msgTypeServicesTargets
	s.kms = p.KMS()
	s.keyType = p.KeyType()
	s.keyAgreementType = p.KeyAgreementType()
	s.allServices = p.AllServices()
	s.listenerFunc = listener(s.callbackChannel, s.handleCallback)

	go s.listenerFunc()

	s.initialized = true

	return nil
}

// Name is this service's name.
func (s *Service) Name() string {
	return Name
}

// Accept determines whether this service can handle the given type of message.
func (s *Service) Accept(msgType string) bool {
	return msgType == InvitationMsgType
}

// HandleInbound handles inbound messages.
func (s *Service) HandleInbound(msg service.DIDCommMsg, didCommCtx service.DIDCommContext) (string, error) {
	logger.Debugf("oob/2.0 inbound message: %s", msg)

	if msg == nil {
		return "", fmt.Errorf("oob/2.0 cannot handle nil inbound message")
	}

	if !s.Accept(msg.Type()) {
		return "", fmt.Errorf("oob/2.0 unsupported message type %s", msg.Type())
	}

	return "", nil
}

// HandleOutbound handles outbound messages.
func (s *Service) HandleOutbound(_ service.DIDCommMsg, _, _ string) (string, error) {
	// TODO implement
	return "", errors.New("oob/2.0 not implemented")
}

// AcceptInvitation from another agent.
//nolint:funlen,gocyclo
func (s *Service) AcceptInvitation(i *Invitation) (string, error) { // nolint: gocognit
	msg := service.NewDIDCommMsgMap(i)

	err := validateInvitationAcceptance(msg, s.myMediaTypeProfiles)
	if err != nil {
		return "", fmt.Errorf("oob/2.0 unable to accept invitation: %w", err)
	}

	clbk := &callback{
		msg: msg,
	}

	err = s.handleCallback(clbk)
	if err != nil {
		return "", fmt.Errorf("oob/2.0 failed to accept invitation : %w", err)
	}

	newDID := &did.Doc{Service: []did.Service{{Type: vdrapi.DIDCommV2ServiceType}}}

	err = s.createNewKeyAndVM(newDID)
	if err != nil {
		return "", fmt.Errorf("oob/2.0 AcceptInvitation: creating new keys and VMS for DID document failed: %w", err)
	}

	// set KeyAgreement.ID as RecipientKeys as part of DIDComm V2 service
	newDID.Service[0].RecipientKeys = []string{newDID.KeyAgreement[0].VerificationMethod.ID}

	if i.Body != nil && i.Body.GoalCode != "" {
		serviceURL := s.msgTypeServicesTargets[i.Body.GoalCode]
		for _, srvc := range s.allServices {
			if strings.Contains(serviceURL, srvc.Name()) {
				connID := s.handleInboundService(serviceURL, srvc, i.Requests, newDID)

				if connID != "" {
					logger.Debugf("oob/2.0 matching target service found for url '%v' and executed, "+
						"oobv2.AcceptInvitation() is done.", serviceURL)
					return connID, nil
				}
			}
		}

		logger.Debugf("oob/2.0 no matching target service found for url '%v', oobv2.AcceptInvitation() is done but"+
			" no target service triggered", serviceURL)
	}

	logger.Debugf("oob/2.0 request body or Goal code is empty, oobv2.AcceptInvitation() is done but no" +
		"target service triggered, generating a new peer DID for the first valid attachment and return it")

	for _, atchmnt := range i.Requests {
		serviceRequest, err := atchmnt.Data.Fetch()
		if err != nil {
			logger.Debugf("oob/2.0 fetching attachment request failed:%v, skipping attachment entry..", err)

			continue
		}

		didCommMsgRequest := service.DIDCommMsgMap{}

		err = didCommMsgRequest.UnmarshalJSON(serviceRequest)
		if err != nil {
			logger.Debugf("oob/2.0 fetching attachment request failed: %v, skipping attachment entry..", err)

			continue
		}

		senderDID, ok := didCommMsgRequest["from"].(string)
		if !ok {
			logger.Debugf("oob/2.0 fetching attachment request does not have from field, skipping " +
				"attachment entry..")

			continue
		}

		senderDoc, err := s.vdrRegistry.Resolve(senderDID)
		if err != nil {
			return "", fmt.Errorf("failed to resolve inviter DID: %w", err)
		}

		myDID, err := s.vdrRegistry.Create(peer.DIDMethod, newDID)
		if err != nil {
			logger.Debugf("oob/2.0 creating new DID via VDR failed: %v, skipping attachment entry..", err)

			continue
		}

		destination, err := service.CreateDestination(senderDoc.DIDDocument)
		if err != nil {
			return "", fmt.Errorf("failed to create destination: %w", err)
		}

		connRecord := &connection.Record{
			ConnectionID:      uuid.New().String(),
			ParentThreadID:    i.ID,
			State:             "null",
			InvitationID:      i.ID,
			ServiceEndPoint:   destination.ServiceEndpoint,
			RecipientKeys:     destination.RecipientKeys,
			RoutingKeys:       destination.RoutingKeys,
			TheirLabel:        i.Label,
			TheirDID:          senderDID,
			Namespace:         "my",
			MediaTypeProfiles: s.myMediaTypeProfiles,
			Implicit:          true,
			InvitationDID:     myDID.DIDDocument.ID,
			DIDCommVersion:    service.V2,
		}

		if err := s.connectionRecorder.SaveConnectionRecord(connRecord); err != nil {
			return "", err
		}

		return connRecord.ConnectionID, nil
	}

	return "", fmt.Errorf("oob/2.0 invitation request has no attachment requests to fulfill request Goal")
}

func (s *Service) handleInboundService(serviceURL string, srvc dispatcher.ProtocolService,
	attachments []*decorator.AttachmentV2, newDID *did.Doc) string {
	for _, atchmnt := range attachments {
		serviceRequest, err := atchmnt.Data.Fetch()
		if err != nil {
			logger.Debugf("oob/2.0 fetching target service '%v' for url '%v' attachment request failed:"+
				" %v, skipping attachment entry..", srvc.Name(), serviceURL, err)

			continue
		}

		didCommMsgRequest := service.DIDCommMsgMap{}

		err = didCommMsgRequest.UnmarshalJSON(serviceRequest)
		if err != nil {
			logger.Debugf("oob/2.0 fetching target service '%v' for url '%v' attachment request failed:"+
				" %v, skipping attachment entry..", srvc.Name(), serviceURL, err)

			continue
		}

		senderDID, ok := didCommMsgRequest["from"]
		if !ok {
			logger.Debugf("oob/2.0 fetching target service '%v' for url '%v' attachment request does not have "+
				"from field, skipping attachment entry..", srvc.Name(), serviceURL)

			continue
		}

		myDID, err := s.vdrRegistry.Create(peer.DIDMethod, newDID)
		if err != nil {
			logger.Debugf("oob/2.0 fetching target service '%v' for url '%v' creating new DID via VDR "+
				"failed: %v, skipping attachment entry..", srvc.Name(), serviceURL, err)

			continue
		}

		// TODO bug: most services don't return a connection ID from handleInbound, we can't expect it from there.
		connID, err := srvc.HandleInbound(didCommMsgRequest, service.NewDIDCommContext(myDID.DIDDocument.ID,
			senderDID.(string), nil))
		if err != nil {
			logger.Debugf("oob/2.0 executing target service '%v' for url '%v' failed: %v, skipping "+
				"attachment entry..", srvc.Name(), serviceURL, err)

			continue
		}

		logger.Debugf("oob/2.0 successfully executed target service '%v' for target url: '%v', returned id: %v",
			srvc.Name(), serviceURL, connID)

		return connID
	}

	return ""
}

// TODO below function and sub functions are copied from pkg/didcomm/protocol/didexchange/keys.go
//      move code in a common location and remove duplicate code.
func (s *Service) createNewKeyAndVM(didDoc *did.Doc) error {
	vm, err := s.createSigningVM()
	if err != nil {
		return err
	}

	kaVM, err := s.createEncryptionVM()
	if err != nil {
		return err
	}

	didDoc.VerificationMethod = append(didDoc.VerificationMethod, *vm)

	didDoc.Authentication = append(didDoc.Authentication, *did.NewReferencedVerification(vm, did.Authentication))
	didDoc.KeyAgreement = append(didDoc.KeyAgreement, *did.NewReferencedVerification(kaVM, did.KeyAgreement))

	return nil
}

// nolint:gochecknoglobals
var vmType = map[kms.KeyType]string{
	kms.ED25519Type:            ed25519VerificationKey2018,
	kms.BLS12381G2Type:         bls12381G2Key2020,
	kms.ECDSAP256TypeDER:       jsonWebKey2020,
	kms.ECDSAP256TypeIEEEP1363: jsonWebKey2020,
	kms.ECDSAP384TypeDER:       jsonWebKey2020,
	kms.ECDSAP384TypeIEEEP1363: jsonWebKey2020,
	kms.ECDSAP521TypeDER:       jsonWebKey2020,
	kms.ECDSAP521TypeIEEEP1363: jsonWebKey2020,
	kms.X25519ECDHKWType:       x25519KeyAgreementKey2019,
	kms.NISTP256ECDHKWType:     jsonWebKey2020,
	kms.NISTP384ECDHKWType:     jsonWebKey2020,
	kms.NISTP521ECDHKWType:     jsonWebKey2020,
}

func getVerMethodType(kt kms.KeyType) string {
	return vmType[kt]
}

func (s *Service) createSigningVM() (*did.VerificationMethod, error) {
	vmType := getVerMethodType(s.keyType)

	_, pubKeyBytes, err := s.kms.CreateAndExportPubKeyBytes(s.keyType)
	if err != nil {
		return nil, fmt.Errorf("createSigningVM: %w", err)
	}

	vmID := "#key-1"

	switch vmType {
	case ed25519VerificationKey2018, bls12381G2Key2020:
		return did.NewVerificationMethodFromBytes(vmID, vmType, "", pubKeyBytes), nil
	case jsonWebKey2020:
		j, err := jwksupport.PubKeyBytesToJWK(pubKeyBytes, s.keyType)
		if err != nil {
			return nil, fmt.Errorf("createSigningVM: failed to convert public key to JWK for VM: %w", err)
		}

		return did.NewVerificationMethodFromJWK(vmID, vmType, "", j)
	default:
		return nil, fmt.Errorf("createSigningVM: unsupported verification method: '%s'", vmType)
	}
}

func (s *Service) createEncryptionVM() (*did.VerificationMethod, error) {
	encKeyType := s.keyAgreementType

	vmType := getVerMethodType(encKeyType)

	_, kaPubKeyBytes, err := s.kms.CreateAndExportPubKeyBytes(encKeyType)
	if err != nil {
		return nil, fmt.Errorf("createEncryptionVM: %w", err)
	}

	vmID := "#key-2"

	switch vmType {
	case x25519KeyAgreementKey2019:
		key := &crypto.PublicKey{}

		err = json.Unmarshal(kaPubKeyBytes, key)
		if err != nil {
			return nil, fmt.Errorf("createEncryptionVM: unable to unmarshal X25519 key: %w", err)
		}

		return did.NewVerificationMethodFromBytes(vmID, vmType, "", key.X), nil
	case jsonWebKey2020:
		j, err := buildJWKFromBytes(kaPubKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("createEncryptionVM: %w", err)
		}

		vm, err := did.NewVerificationMethodFromJWK(vmID, vmType, "", j)
		if err != nil {
			return nil, fmt.Errorf("createEncryptionVM: %w", err)
		}

		return vm, nil
	default:
		return nil, fmt.Errorf("unsupported verification method for KeyAgreement: '%s'", vmType)
	}
}

func buildJWKFromBytes(pubKeyBytes []byte) (*jwk.JWK, error) {
	pubKey := &crypto.PublicKey{}

	err := json.Unmarshal(pubKeyBytes, pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWK for KeyAgreement: %w", err)
	}

	var j *jwk.JWK

	switch pubKey.Type {
	case "EC":
		ecKey, err := crypto.ToECKey(pubKey)
		if err != nil {
			return nil, err
		}

		j = &jwk.JWK{
			JSONWebKey: gojose.JSONWebKey{
				Key:   ecKey,
				KeyID: pubKey.KID,
			},
			Kty: pubKey.Type,
			Crv: pubKey.Curve,
		}
	case "OKP":
		j = &jwk.JWK{
			JSONWebKey: gojose.JSONWebKey{
				Key:   pubKey.X,
				KeyID: pubKey.KID,
			},
			Kty: pubKey.Type,
			Crv: pubKey.Curve,
		}
	}

	return j, nil
}

func listener(
	callbacks chan *callback,
	handleCallbackFunc func(*callback) error) func() {
	return func() {
		for c := range callbacks {
			switch c.msg.Type() {
			case InvitationMsgType:
				err := handleCallbackFunc(c)
				if err != nil {
					logutil.LogError(logger, Name, "handleCallback", err.Error(),
						logutil.CreateKeyValueString("msgType", c.msg.Type()),
						logutil.CreateKeyValueString("msgID", c.msg.ID()))

					continue
				}
			default:
				logutil.LogError(logger, Name, "callbackChannel", "oob/2.0 unsupported msg type",
					logutil.CreateKeyValueString("msgType", c.msg.Type()),
					logutil.CreateKeyValueString("msgID", c.msg.ID()))
			}
		}
	}
}

func (s *Service) handleCallback(c *callback) error {
	switch c.msg.Type() {
	case InvitationMsgType:
		return s.handleInvitationCallback(c)
	default:
		return fmt.Errorf("unsupported message type: %s", c.msg.Type())
	}
}

func (s *Service) handleInvitationCallback(c *callback) error {
	logger.Debugf("oob/2.0 input: %+v", c)

	err := validateInvitationAcceptance(c.msg, s.myMediaTypeProfiles)
	if err != nil {
		return fmt.Errorf("unable to handle invitation: %w", err)
	}

	return nil
}

func validateInvitationAcceptance(msg service.DIDCommMsg, myProfiles []string) error {
	if msg.Type() != InvitationMsgType {
		return nil
	}

	inv := &Invitation{}

	err := msg.Decode(inv)
	if err != nil {
		return fmt.Errorf("validateInvitationAcceptance: failed to decode invitation: %w", err)
	}

	if !matchMediaTypeProfiles(inv.Body.Accept, myProfiles) {
		return fmt.Errorf("no acceptable media type profile found in invitation, invitation Accept property: [%v], "+
			"agent mediatypeprofiles: [%v]", inv.Body.Accept, myProfiles)
	}

	return nil
}

func matchMediaTypeProfiles(theirProfiles, myProfiles []string) bool {
	if theirProfiles == nil {
		// we use our preferred media type profile instead of confirming an overlap exists
		return true
	}

	if myProfiles == nil {
		myProfiles = transport.MediaTypeProfiles()
	}

	profiles := list2set(myProfiles)

	for _, a := range theirProfiles {
		if _, valid := profiles[a]; valid {
			return true
		}
	}

	return false
}

func list2set(list []string) map[string]struct{} {
	set := map[string]struct{}{}

	for _, e := range list {
		set[e] = struct{}{}
	}

	return set
}
