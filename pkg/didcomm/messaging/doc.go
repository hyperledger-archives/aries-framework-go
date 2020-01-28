/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

// Package messaging provides message service features which enables agent framework to handle any incoming
// DIDComm message based on their type and purpose. Incoming message of type not handled by any of the existing
// protocol services will be handled by available message service of matching type and purpose.
//
// This package provides message service provider implementation `msghandler` which can be used to maintain list of
// available message services.
// (RFC Reference : https://github.com/hyperledger/aries-rfcs/blob/master/features/0351-purpose-decorator/README.md)
//
// This package also provides custom message service implementation under `service` package,
// one which is `service/http` for `http-over-didcomm` service.
// (RFC Reference : https://github.com/hyperledger/aries-rfcs/blob/master/features/0335-http-over-didcomm/README.md)
package messaging
