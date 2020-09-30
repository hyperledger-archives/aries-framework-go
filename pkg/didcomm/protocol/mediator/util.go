/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import (
	"errors"
	"fmt"
)

// GetRouterConfig util to get the router configuration. The endpoint is overridden with routers endpoint,
// if router is registered. Returns endpoint, routingKeys and error.
func GetRouterConfig(routeSvc ProtocolService, connID, endpoint string) (string, []string, error) {
	routeConf, err := routeSvc.Config(connID)
	if err != nil && !errors.Is(err, ErrRouterNotRegistered) {
		return "", nil, fmt.Errorf("fetch router config: %w", err)
	}

	if routeConf != nil {
		return routeConf.Endpoint(), routeConf.Keys(), nil
	}

	return endpoint, nil, nil
}

// AddKeyToRouter util to add the recipient keys to the router.
func AddKeyToRouter(routeSvc ProtocolService, connID, recKey string) error {
	if err := routeSvc.AddKey(connID, recKey); err != nil && !errors.Is(err, ErrRouterNotRegistered) {
		return fmt.Errorf("addKey: %w", err)
	}

	return nil
}
