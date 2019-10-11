/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// CloseableWallet interface
type CloseableWallet interface {
	io.Closer
	wallet.Crypto
	wallet.Signer
	wallet.DIDCreator
}

// WalletCreator method to create new wallet service
type WalletCreator func(provider Provider) (CloseableWallet, error)
