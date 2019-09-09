/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package provider

import "github.com/hyperledger/aries-framework-go/pkg/wallet"

// Provider mocks provider needed for did exchange service initialization
type Provider struct {
	ServiceValue interface{}
	ServiceErr   error
	WalletValue  wallet.Crypto
}

// Service return service
func (p *Provider) Service(id string) (interface{}, error) {
	return p.ServiceValue, p.ServiceErr
}

// CryptoWallet return crypto wallet
func (p *Provider) CryptoWallet() wallet.Crypto {
	return p.WalletValue
}
