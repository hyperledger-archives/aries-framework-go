/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// OutboundDispatcher dispatch msgs to destination
type OutboundDispatcher struct {
	outboundTransports []transport.OutboundTransport
	wallet             wallet.Pack
}

// NewOutbound return new dispatcher outbound instance
func NewOutbound(prov Provider) *OutboundDispatcher {
	return &OutboundDispatcher{outboundTransports: prov.OutboundTransports(), wallet: prov.PackWallet()}
}

// Send msg
func (o *OutboundDispatcher) Send(msg interface{}, senderVerKey string, des *Destination) error {
	for _, v := range o.outboundTransports {
		if v.Accept(des.ServiceEndpoint) {
			bytes, err := json.Marshal(msg)
			if err != nil {
				return fmt.Errorf("failed marshal to bytes: %w", err)
			}
			packedMsg, err := o.wallet.PackMessage(&wallet.Envelope{Message: bytes, FromVerKey: senderVerKey, ToVerKeys: des.RecipientKeys})
			if err != nil {
				return fmt.Errorf("failed to pack msg: %w", err)
			}
			// TODO should we return respData from send
			_, err = v.Send(packedMsg, des.ServiceEndpoint)
			if err != nil {
				return fmt.Errorf("failed to send msg using http outbound transport: %w", err)
			}
			return nil
		}
	}
	return fmt.Errorf("no outbound transport found for serviceEndpoint: %s", des.ServiceEndpoint)
}
