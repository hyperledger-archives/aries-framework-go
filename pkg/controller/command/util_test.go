/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

func Test_WriteNillableResponse(t *testing.T) {
	WriteNillableResponse(&mockWriter{}, nil, log.New("test"))
}

type mockWriter struct{}

func (m *mockWriter) Write(p []byte) (n int, err error) {
	return 0, nil
}
