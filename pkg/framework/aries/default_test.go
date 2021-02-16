/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/spi/storage"
	verifiableStoreMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/store/verifiable"
)

func TestDefaultFramework(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("test default framework - success", func(t *testing.T) {
		aries := &Aries{}
		err := defFrameworkOpts(aries)
		require.NoError(t, err)
	})

	t.Run("test with provided store - success", func(t *testing.T) {
		mockStore := verifiableStoreMocks.NewMockStore(ctrl)
		aries := &Aries{verifiableStore: mockStore}
		err := defFrameworkOpts(aries)
		require.NoError(t, err)
		require.Equal(t, mockStore, aries.verifiableStore)
	})
}

func TestCreateVerifiableStore(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("test with store provider - error", func(t *testing.T) {
		storeProvider := mocks.NewMockProvider(ctrl)
		storeProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, errors.New("some error"))
		err := assignVerifiableStoreIfNeeded(&Aries{}, storeProvider)
		require.Error(t, err)
	})
}
