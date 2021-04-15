/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

/* const (
	legacyMediaType			 = "JWM/1.0"
	didCommV1MediaType       = "application/didcomm-enc-env"
	didCommV2MediaType       = "application/didcomm-encrypted+json"
) */

// provider interface for outbound ctx.
type provider interface {
	Packager() transport.Packager
	OutboundTransports() []transport.OutboundTransport
	TransportReturnRoute() string
	VDRegistry() vdr.Registry
	KMS() kms.KeyManager
}

// OutboundDispatcher dispatch msgs to destination.
type OutboundDispatcher struct {
	outboundTransports   []transport.OutboundTransport
	packager             transport.Packager
	transportReturnRoute string
	vdRegistry           vdr.Registry
	kms                  kms.KeyManager
}

// NewOutbound return new dispatcher outbound instance.
func NewOutbound(prov provider) *OutboundDispatcher {
	return &OutboundDispatcher{
		outboundTransports:   prov.OutboundTransports(),
		packager:             prov.Packager(),
		transportReturnRoute: prov.TransportReturnRoute(),
		vdRegistry:           prov.VDRegistry(),
		kms:                  prov.KMS(),
	}
}

// SendToDID sends a message from myDID to the agent who owns theirDID.
func (o *OutboundDispatcher) SendToDID(msg interface{}, myDID, theirDID string) error {
	dest, err := service.GetDestination(theirDID, o.vdRegistry)
	if err != nil {
		return fmt.Errorf(
			"outboundDispatcher.SendToDID failed to get didcomm destination for theirDID [%s]: %w", theirDID, err)
	}

	src, err := service.GetDestination(myDID, o.vdRegistry)
	if err != nil {
		return fmt.Errorf("outboundDispatcher.SendToDID failed to get didcomm destination for myDID [%s]: %w", myDID, err)
	}

	// We get at least one recipient key, so we can use the first one
	//  (right now, with only one key type used for sending)
	// TODO: relies on hardcoded key type
	key := src.RecipientKeys[0]

	return o.Send(msg, key, dest)
}

// Send sends the message after packing with the sender key and recipient keys.
// nolint:gocyclo
func (o *OutboundDispatcher) Send(msg interface{}, senderVerKey string, des *service.Destination) error {
	for _, v := range o.outboundTransports {
		// check if outbound accepts routing keys, else use recipient keys
		keys := des.RecipientKeys
		if len(des.RoutingKeys) != 0 {
			keys = des.RoutingKeys
		}

		if !v.AcceptRecipient(keys) {
			if !v.Accept(des.ServiceEndpoint) {
				continue
			}
		}

		req, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("outboundDispatcher.Send: failed marshal to bytes: %w", err)
		}

		// update the outbound message with transport return route option [all or thread]
		req, err = o.addTransportRouteOptions(req, des)
		if err != nil {
			return fmt.Errorf("outboundDispatcher.Send: failed to add transport route options : %w", err)
		}

		sender, err := fingerprint.PubKeyFromDIDKey(senderVerKey)
		if err != nil {
			return fmt.Errorf("outboundDispatcher.Send: failed to extract pubKeyBytes from senderVerKey: %w", err)
		}

		packedMsg, err := o.packager.PackMessage(&transport.Envelope{
			MediaType: mediaType(des),
			Message:   req,
			FromKey:   sender,
			ToKeys:    des.RecipientKeys,
		})
		if err != nil {
			return fmt.Errorf("outboundDispatcher.Send: failed to pack msg: %w", err)
		}

		// set the return route option
		des.TransportReturnRoute = o.transportReturnRoute

		packedMsg, err = o.createForwardMessage(packedMsg, des)
		if err != nil {
			return fmt.Errorf("outboundDispatcher.Send: failed to create forward msg : %w", err)
		}

		_, err = v.Send(packedMsg, des)
		if err != nil {
			return fmt.Errorf("outboundDispatcher.Send: failed to send msg using outbound transport: %w", err)
		}

		return nil
	}

	return fmt.Errorf("outboundDispatcher.Send: no transport found for destination: %+v", des)
}

// Forward forwards the message without packing to the destination.
func (o *OutboundDispatcher) Forward(msg interface{}, des *service.Destination) error {
	for _, v := range o.outboundTransports {
		if !v.AcceptRecipient(des.RecipientKeys) {
			if !v.Accept(des.ServiceEndpoint) {
				continue
			}
		}

		req, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("outboundDispatcher.Forward: failed marshal to bytes: %w", err)
		}

		_, err = v.Send(req, des)
		if err != nil {
			return fmt.Errorf("outboundDispatcher.Forward: failed to send msg using outbound transport: %w", err)
		}

		return nil
	}

	return fmt.Errorf("outboundDispatcher.Forward: no transport found for serviceEndpoint: %s", des.ServiceEndpoint)
}

func (o *OutboundDispatcher) createForwardMessage(msg []byte, des *service.Destination) ([]byte, error) {
	if len(des.RoutingKeys) == 0 {
		return msg, nil
	}

	env := &model.Envelope{}

	err := json.Unmarshal(msg, env)
	if err != nil {
		return nil, fmt.Errorf("unmarshal envelope : %w", err)
	}
	// create forward message
	forward := &model.Forward{
		Type: service.ForwardMsgType,
		ID:   uuid.New().String(),
		To:   des.RecipientKeys[0],
		Msg:  env,
	}

	// convert forward message to bytes
	req, err := json.Marshal(forward)
	if err != nil {
		return nil, fmt.Errorf("failed marshal to bytes: %w", err)
	}

	// create key set
	_, senderVerKey, err := o.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("failed Create and export SigningKey: %w", err)
	}

	// pack above message using auth crypt
	// TODO https://github.com/hyperledger/aries-framework-go/issues/1112 Configurable packing
	//  algorithm(auth/anon crypt) for Forward(router) message

	packedMsg, err := o.packager.PackMessage(&transport.Envelope{
		MediaType: mediaType(des),
		Message:   req,
		FromKey:   senderVerKey,
		ToKeys:    des.RoutingKeys,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to pack forward msg: %w", err)
	}

	return packedMsg, nil
}

func (o *OutboundDispatcher) addTransportRouteOptions(req []byte, des *service.Destination) ([]byte, error) {
	// dont add transport route options for forward messages
	if len(des.RoutingKeys) != 0 {
		return req, nil
	}

	if o.transportReturnRoute == decorator.TransportReturnRouteAll ||
		o.transportReturnRoute == decorator.TransportReturnRouteThread {
		// create the decorator with the option set in the framework
		transportDec := &decorator.Transport{ReturnRoute: &decorator.ReturnRoute{Value: o.transportReturnRoute}}

		transportDecJSON, jsonErr := json.Marshal(transportDec)
		if jsonErr != nil {
			return nil, fmt.Errorf("json marshal : %w", jsonErr)
		}

		request := string(req)
		index := strings.Index(request, "{")

		// add transport route option decorator to the original request
		req = []byte(request[:index+1] + string(transportDecJSON)[1:len(string(transportDecJSON))-1] + "," +
			request[index+1:])
	}

	return req, nil
}

// TODO - inject MediaType selection strategy.
func mediaType(des *service.Destination) string {
	mt := ""
	if len(des.MediaTypes) > 0 {
		mt = des.MediaTypes[0]
	}

	return mt
}
