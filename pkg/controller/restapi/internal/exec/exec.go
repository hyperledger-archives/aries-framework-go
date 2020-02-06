/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package exec

import (
	"io"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	resterrors "github.com/hyperledger/aries-framework-go/pkg/controller/restapi/errors"
)

// Command executes given command with args provided and writes error to
// response writer
func Command(exec command.Exec, rw http.ResponseWriter, req io.Reader) {
	err := exec(rw, req)
	if err != nil {
		resterrors.SendError(rw, err)
	}
}
