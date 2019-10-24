/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/didcreator"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/wallet"
)

// CloseableWallet interface
type CloseableWallet interface {
	io.Closer
	wallet.Crypto
	wallet.Signer
	didcreator.DIDCreator
}

// WalletCreator method to create new wallet service
type WalletCreator func(provider Provider) (CloseableWallet, error)
