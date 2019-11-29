/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	commontransport "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

// provider interface for outbound ctx
type provider interface {
	Packager() commontransport.Packager
	OutboundTransports() []transport.OutboundTransport
	TransportReturnRoute() string
}

// OutboundDispatcher dispatch msgs to destination
type OutboundDispatcher struct {
	outboundTransports   []transport.OutboundTransport
	packager             commontransport.Packager
	transportReturnRoute string
}

// NewOutbound return new dispatcher outbound instance
func NewOutbound(prov provider) *OutboundDispatcher {
	return &OutboundDispatcher{
		outboundTransports:   prov.OutboundTransports(),
		packager:             prov.Packager(),
		transportReturnRoute: prov.TransportReturnRoute(),
	}
}

// Send msg
func (o *OutboundDispatcher) Send(msg interface{}, senderVerKey string, des *service.Destination) error {
	for _, v := range o.outboundTransports {
		if !v.Accept(des.ServiceEndpoint) {
			continue
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
			&commontransport.Envelope{Message: req, FromVerKey: senderVerKey, ToVerKeys: des.RecipientKeys})
		if err != nil {
			return fmt.Errorf("failed to pack msg: %w", err)
		}

		_, err = v.Send(packedMsg, des)
		if err != nil {
			return fmt.Errorf("failed to send msg using http outbound transport: %w", err)
		}

		return nil
	}

	return fmt.Errorf("no outbound transport found for serviceEndpoint: %s", des.ServiceEndpoint)
}
