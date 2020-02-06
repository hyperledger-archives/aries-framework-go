/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package exec

import (
	"fmt"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
)

func TestCommand(t *testing.T) {
	cmd := func(rw io.Writer, req io.Reader) command.Error {
		return command.NewValidationError(1, fmt.Errorf("sample"))
	}

	rw := httptest.NewRecorder()
	Command(cmd, rw, nil)
	require.Contains(t, rw.Body.String(), `{"code":1,"message":"sample"}`)
}
