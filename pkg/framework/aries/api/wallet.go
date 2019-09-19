/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// CloseableWallet interface
type CloseableWallet interface {
	io.Closer
	wallet.Crypto
	wallet.Pack
	wallet.DIDCreator
}

// WalletCreator method to create new wallet service
type WalletCreator func(storeProvider storage.Provider) (CloseableWallet, error)
