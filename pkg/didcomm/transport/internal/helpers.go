/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package internal

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

var logger = log.New("didcomm/transport/internal")

// UnpackMessage using 'pack' with a 'source' of either 'ws' or 'http'.
func UnpackMessage(message []byte, pack transport.Packager, source string) (*transport.Envelope, error) {
	doubleQuote := []byte("\"")
	msg := message

	if bytes.HasPrefix(message, doubleQuote) && bytes.HasSuffix(message, doubleQuote) {
		logger.Debugf("unpack msg from %s is wrapped with double quotes trying to base64 decode before unpacking..",
			source)

		msg = msg[1 : len(msg)-1]

		var decodedMsg []byte

		decodedMsg1, err1 := base64.URLEncoding.DecodeString(string(msg))
		decodedMsg2, err2 := base64.RawURLEncoding.DecodeString(string(msg))

		switch {
		case err1 == nil:
			decodedMsg = decodedMsg1
		case err2 == nil:
			decodedMsg = decodedMsg2
		default:
			return nil, fmt.Errorf("not base64 encoded message error from %s: URLEncoding error: %w, RawURLEncoding"+
				" error: %v", source, err1, err2)
		}

		msg = decodedMsg
	}

	unpackMsg, err := pack.UnpackMessage(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack msg from %s: %w", source, err)
	}

	return unpackMsg, nil
}
