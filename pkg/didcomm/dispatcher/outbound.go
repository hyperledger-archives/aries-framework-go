/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	commontransport "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

// provider interface for outbound ctx
type provider interface {
	Packager() commontransport.Packager
	OutboundTransports() []transport.OutboundTransport
}

// OutboundDispatcher dispatch msgs to destination
type OutboundDispatcher struct {
	outboundTransports []transport.OutboundTransport
	packager           commontransport.Packager
}

// NewOutbound return new dispatcher outbound instance
func NewOutbound(prov provider) *OutboundDispatcher {
	return &OutboundDispatcher{outboundTransports: prov.OutboundTransports(), packager: prov.Packager()}
}

// Send msg
func (o *OutboundDispatcher) Send(msg interface{}, senderVerKey string, des *service.Destination) error {
	for _, v := range o.outboundTransports {
		if !v.Accept(des.ServiceEndpoint) {
			continue
		}

		bytes, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("failed marshal to bytes: %w", err)
		}

		packedMsg, err := o.packager.PackMessage(
			&commontransport.Envelope{Message: bytes, FromVerKey: senderVerKey, ToVerKeys: des.RecipientKeys})
		if err != nil {
			return fmt.Errorf("failed to pack msg: %w", err)
		}

		_, err = v.Send(packedMsg, des.ServiceEndpoint)
		if err != nil {
			return fmt.Errorf("failed to send msg using http outbound transport: %w", err)
		}

		return nil
	}

	return fmt.Errorf("no outbound transport found for serviceEndpoint: %s", des.ServiceEndpoint)
}
