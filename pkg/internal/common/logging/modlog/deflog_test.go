/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modlog

import (
	"fmt"
	"log"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/internal/common/logging/metadata"
)

func TestDefLog(t *testing.T) {
	const module = "sample-module"
	defLog := &defLog{logger: log.New(&buf, fmt.Sprintf(logPrefixFormatter, module), log.Ldate|log.Ltime|log.LUTC), module: module}

	logger := &modLog{defLog, module}
	VerifyDefaultLogging(t, logger, module, metadata.SetLevel)
}
