/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package embed

import (
	embedcontexts "github.com/hyperledger/aries-framework-go/component/models/ld/context/embed"
)

// Contexts contains JSON-LD contexts embedded into a Go binary.
var Contexts = embedcontexts.Contexts // nolint:gochecknoglobals
