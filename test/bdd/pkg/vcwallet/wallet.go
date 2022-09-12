/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"encoding/base64"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

const (
	samplePassPhrase = "youshallnotpass"
	sampleUser       = "sampleUser"
)

func (s *SDKSteps) createWalletProfile(holder string) error {
	provider := &mockprovider.Provider{
		DocumentLoaderValue:               s.bddContext.AgentCtx[holder].JSONLDDocumentLoader(),
		StorageProviderValue:              mockstorage.NewMockStoreProvider(),
		ProtocolStateStorageProviderValue: mockstorage.NewMockStoreProvider(),
		CryptoValue:                       s.bddContext.AgentCtx[holder].Crypto(),
		VDRegistryValue:                   s.bddContext.AgentCtx[holder].VDRegistry(),
	}

	err := wallet.CreateProfile(sampleUser, provider, wallet.WithPassphrase(samplePassPhrase))
	if err != nil {
		return err
	}

	s.walletProvider = provider

	return nil
}

func (s *SDKSteps) openWallet(holder string) error {
	walletInstance, err := wallet.New(sampleUser, s.walletProvider)
	if err != nil {
		return err
	}

	token, err := walletInstance.Open(wallet.WithUnlockByPassphrase(samplePassPhrase))
	if err != nil {
		return err
	}

	s.wallet = walletInstance
	s.token = token

	return nil
}

func (s *SDKSteps) closeWallet(holder string) error {
	walletInstance := s.wallet
	if walletInstance == nil {
		return fmt.Errorf("empty wallet")
	}

	walletInstance.Close()

	return nil
}

func (s *SDKSteps) createKeyPairWallet(agent, crypto string) error {
	walletInstance := s.wallet
	if walletInstance == nil {
		return fmt.Errorf("empty wallet")
	}

	keyType := mapCryptoKeyType(crypto)

	keyPair, err := walletInstance.CreateKeyPair(s.token, keyType)
	if err != nil {
		return err
	}

	kid := keyPair.KeyID

	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(keyPair.PublicKey)
	if err != nil {
		return err
	}

	pubKeyJWK, err := jwksupport.PubKeyBytesToJWK(pubKeyBytes, keyType)
	if err != nil {
		return err
	}

	s.bddContext.PublicKeys[agent] = pubKeyJWK
	s.keyIds[agent] = kid

	return nil
}
