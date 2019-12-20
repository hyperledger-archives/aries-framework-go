/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	commontransport "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
)

// provider interface for outbound ctx
type provider interface {
	Packager() commontransport.Packager
	OutboundTransports() []transport.OutboundTransport
	TransportReturnRoute() string
	VDRIRegistry() vdri.Registry
}

// OutboundDispatcher dispatch msgs to destination
type OutboundDispatcher struct {
	outboundTransports   []transport.OutboundTransport
	packager             commontransport.Packager
	transportReturnRoute string
	vdRegistry           vdri.Registry
}

// NewOutbound return new dispatcher outbound instance
func NewOutbound(prov provider) *OutboundDispatcher {
	return &OutboundDispatcher{
		outboundTransports:   prov.OutboundTransports(),
		packager:             prov.Packager(),
		transportReturnRoute: prov.TransportReturnRoute(),
		vdRegistry:           prov.VDRIRegistry(),
	}
}

// SendToDID sends a message from myDID to the agent who owns theirDID
func (o *OutboundDispatcher) SendToDID(msg interface{}, myDID, theirDID string) error {
	dest, err := service.GetDestination(theirDID, o.vdRegistry)
	if err != nil {
		return err
	}

	src, err := service.GetDestination(myDID, o.vdRegistry)
	if err != nil {
		return err
	}

	// We get at least one recipient key, so we can use the first one
	//  (right now, with only one key type used for sending)
	// TODO: relies on hardcoded key type
	key := src.RecipientKeys[0]

	return o.Send(msg, key, dest)
}

// Send sends the message after packing with the sender key and recipient keys.
func (o *OutboundDispatcher) Send(msg interface{}, senderVerKey string, des *service.Destination) error {
	for _, v := range o.outboundTransports {
		if !v.AcceptRecipient(des.RecipientKeys) {
			if !v.Accept(des.ServiceEndpoint) {
				continue
			}
		}

		req, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("failed marshal to bytes: %w", err)
		}

		// update the outbound message with transport return route option [all or thread]
		if o.transportReturnRoute == decorator.TransportReturnRouteAll ||
			o.transportReturnRoute == decorator.TransportReturnRouteThread {
			// create the decorator with the option set in the framework
			transportDec := &decorator.Transport{ReturnRoute: &decorator.ReturnRoute{Value: o.transportReturnRoute}}

			transportDecJSON, jsonErr := json.Marshal(transportDec)
			if jsonErr != nil {
				return fmt.Errorf("json marshal : %w", jsonErr)
			}

			request := string(req)
			index := strings.Index(request, "{")

			// add transport route option decorator to the original request
			req = []byte(request[:index+1] + string(transportDecJSON)[1:len(string(transportDecJSON))-1] + "," +
				request[index+1:])
		}

		packedMsg, err := o.packager.PackMessage(
			&commontransport.Envelope{Message: req, FromVerKey: base58.Decode(senderVerKey), ToVerKeys: des.RecipientKeys})
		if err != nil {
			return fmt.Errorf("failed to pack msg: %w", err)
		}

		// set the return route option
		des.TransportReturnRoute = o.transportReturnRoute

		packedMsg = createForwardMessage(packedMsg, des)

		_, err = v.Send(packedMsg, des)
		if err != nil {
			return fmt.Errorf("failed to send msg using outbound transport: %w", err)
		}

		return nil
	}

	return fmt.Errorf("no outbound transport found for serviceEndpoint: %s", des.ServiceEndpoint)
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
			return fmt.Errorf("failed marshal to bytes: %w", err)
		}

		_, err = v.Send(req, des)
		if err != nil {
			return fmt.Errorf("failed to send msg using outbound transport: %w", err)
		}

		return nil
	}

	return fmt.Errorf("no outbound transport found for serviceEndpoint: %s", des.ServiceEndpoint)
}

func createForwardMessage(msg []byte, des *service.Destination) []byte {
	// TODO https://github.com/hyperledger/aries-framework-go/issues/807#issuecomment-566126744 message needs to
	//  be packed with anon crypt if the request needs through routed ie. des.RoutingKeys != nil
	//  psuedocode:
	//		if des.RoutingKeys != nil {
	//			// create forward message:
	//			forward := &Forward{
	//				Type: "https://didcomm.org/routing/1.0/forward",
	//				ID:   uuid.New().String(),
	//				To:   "destinationRecKey",
	//				Msg:  packedMsg,
	//			}
	//
	//			// pack above message using anon crypt
	//
	//			// return the message
	//		}
	return msg
}
