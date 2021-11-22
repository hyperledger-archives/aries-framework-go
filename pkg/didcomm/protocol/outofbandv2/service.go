/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofbandv2

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// Name of this protocol service.
	Name = "out-of-band/2.0"
	// PIURI is the Out-of-Band protocol's protocol instance URI.
	PIURI = "https://didcomm.org/" + Name
	// InvitationMsgType is the '@type' for the invitation message.
	InvitationMsgType = PIURI + "/invitation"

	// TODO channel size - https://github.com/hyperledger/aries-framework-go/issues/246
	callbackChannelSize = 10

	contextKey = "context_%s"
)

var logger = log.New(fmt.Sprintf("aries-framework/%s/service", Name))

// Service implements the Out-Of-Band V2 protocol.
type Service struct {
	service.Action
	service.Message
	callbackChannel        chan *callback
	transientStore         storage.Store
	inboundHandler         func() service.InboundHandler
	listenerFunc           func()
	messenger              service.Messenger
	myMediaTypeProfiles    []string
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
	ProtocolStateStorageProvider() storage.Provider
	InboundDIDCommMessageHandler() func() service.InboundHandler
	Messenger() service.Messenger
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

	store, err := p.ProtocolStateStorageProvider().OpenStore(Name)
	if err != nil {
		return fmt.Errorf("oob/2.0 failed to open the transientStore : %w", err)
	}

	err = p.ProtocolStateStorageProvider().SetStoreConfig(Name,
		storage.StoreConfiguration{TagNames: []string{contextKey}})
	if err != nil {
		return fmt.Errorf("oob/2.0 failed to set transientStore config in protocol state transientStore: %w", err)
	}

	msgTypeServicesTargets := map[string]string{}

	for _, v := range p.ServiceMsgTypeTargets() {
		msgTypeServicesTargets[v.Target] = v.MsgType
	}

	s.callbackChannel = make(chan *callback, callbackChannelSize)
	s.transientStore = store
	s.inboundHandler = p.InboundDIDCommMessageHandler()
	s.messenger = p.Messenger()
	s.myMediaTypeProfiles = p.MediaTypeProfiles()
	s.msgTypeServicesTargets = msgTypeServicesTargets
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
func (s *Service) AcceptInvitation(i *Invitation) error {
	msg := service.NewDIDCommMsgMap(i)

	err := validateInvitationAcceptance(msg, s.myMediaTypeProfiles)
	if err != nil {
		return fmt.Errorf("oob/2.0 unable to accept invitation: %w", err)
	}

	clbk := &callback{
		msg: msg,
	}

	err = s.handleCallback(clbk)
	if err != nil {
		return fmt.Errorf("oob/2.0 failed to accept invitation : %w", err)
	}

	if i.Body != nil && i.Body.GoalCode != "" {
		serviceURL := s.msgTypeServicesTargets[i.Body.GoalCode]
		for _, srvc := range s.allServices {
			if strings.Contains(serviceURL, srvc.Name()) {
				isHandled := handleInboundService(serviceURL, srvc, i.Requests)

				if isHandled {
					logger.Debugf("oob/2.0 matching target service found for url '%v' and executed, "+
						"oobv2.AcceptInvitation() is done.", serviceURL)
					return nil
				}
			}
		}

		logger.Debugf("oob/2.0 no matching target service found for url '%v', oobv2.AcceptInvitation() is done but"+
			" no target service triggered", serviceURL)
	}

	logger.Debugf("oob/2.0 request body or Goal code is empty, oobv2.AcceptInvitation() is done but no" +
		"target service triggered")

	return nil
}

func handleInboundService(serviceURL string, srvc dispatcher.ProtocolService,
	attachments []*decorator.AttachmentV2) bool {
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

		id, err := srvc.HandleInbound(didCommMsgRequest, service.EmptyDIDCommContext())
		if err != nil {
			logger.Debugf("oob/2.0 executing target service '%v' for url '%v' failed: %v, skipping "+
				"attachment entry..", srvc.Name(), serviceURL, err)

			continue
		}

		logger.Debugf("oob/2.0 successfully executed target service '%v' for target url: '%v', returned id: %v",
			srvc.Name(), serviceURL, id)

		return true
	}

	return false
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
