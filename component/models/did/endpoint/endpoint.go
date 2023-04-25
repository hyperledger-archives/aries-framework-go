/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package endpoint

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// EndpointType endpoint type.
type EndpointType int // nolint: golint

const (
	// DIDCommV1 type.
	DIDCommV1 EndpointType = iota
	// DIDCommV2 type.
	DIDCommV2
	// Generic type.
	Generic
)

// ServiceEndpoint api for fetching ServiceEndpoint content based off of a DIDComm V1, V2 or DIDCore format.
type ServiceEndpoint interface {
	URI() (string, error)
	Accept() ([]string, error)
	RoutingKeys() ([]string, error)
	Type() EndpointType
}

// Endpoint contains endpoint specific content. Content of ServiceEndpoint api above will be used by priority:
// 1- DIDcomm V2
// 2- DIDComm V1
// 3- DIDCore
// To force lower priority endpoint content, avoid setting higher priority data during Unmarshal() execution.
type Endpoint struct {
	rawDIDCommV2 []DIDCommV2Endpoint
	rawDIDCommV1 string
	rawObj       interface{}
}

// DIDCommV2Endpoint contains ServiceEndpoint data specifically for DIDcommV2 and is wrapped in Endpoint as an array.
type DIDCommV2Endpoint struct {
	// URI contains the endpoint URI.
	URI string `json:"uri"`
	// Accept contains the MediaType profiles accepted by this endpoint.
	Accept []string `json:"accept,omitempty"`
	// RoutingKeys contains the list of keys trusted as routing keys for the mediators/routers of this endpoint.
	RoutingKeys []string `json:"routingKeys,omitempty"`
}

// NewDIDCommV2Endpoint creates a DIDCommV2 endpoint with the given array of endpoints. At the time of writing this
// comment, only the first endpoint is effective in the API. Additional logic is required to use a different index.
func NewDIDCommV2Endpoint(endpoints []DIDCommV2Endpoint) Endpoint {
	endpoint := Endpoint{rawDIDCommV2: []DIDCommV2Endpoint{}}
	endpoint.rawDIDCommV2 = append(endpoint.rawDIDCommV2, endpoints...)

	return endpoint
}

// NewDIDCommV1Endpoint creates a DIDCommV1 endpoint.
func NewDIDCommV1Endpoint(uri string) Endpoint {
	return Endpoint{
		rawDIDCommV1: uri,
	}
}

// NewDIDCoreEndpoint creates a generic DIDCore endpoint.
func NewDIDCoreEndpoint(genericEndpoint interface{}) Endpoint {
	return Endpoint{
		rawObj: genericEndpoint,
	}
}

// URI is the URI of a service endpoint.
// It will return the value based on the underlying endpoint type in the following order:
// 1- DIDComm V2 URI (currently the first element's URI). TODO enhance API to pass in an optional index.
// 2- DIDComm V1 URI
// 3- DIDCore's first element printed as string for now. (not used by AFGO at the time of this writing, but can be
//
//	enhanced if needed).
func (s *Endpoint) URI() (string, error) {
	// TODO for now, returning URI of first element. Add mechanism to fetch from appropriate index.
	if len(s.rawDIDCommV2) > 0 {
		return s.rawDIDCommV2[0].URI, nil
	}

	if s.rawDIDCommV1 != "" {
		return stripQuotes(s.rawDIDCommV1), nil
	}

	if s.rawObj != nil {
		switch o := s.rawObj.(type) {
		case []string:
			return o[0], nil
		case [][]byte:
			return string(o[0]), nil
		case []interface{}:
			return fmt.Sprintf("%s", o[0]), nil
		case map[string]interface{}:
			switch uri := o["origins"].(type) {
			case []interface{}:
				return fmt.Sprintf("%s", uri[0]), nil
			default:
				return "", fmt.Errorf("unrecognized DIDCore origins object %s", o)
			}
		default:
			return "", fmt.Errorf("unrecognized DIDCore endpoint object %s", o)
		}
	}

	return "", fmt.Errorf("endpoint URI not found")
}

// Accept is the DIDComm V2 Accept field of a service endpoint.
func (s *Endpoint) Accept() ([]string, error) {
	// TODO for now, returning Accept of first element. Add mechanism to fetch appropriate value.
	if len(s.rawDIDCommV2) > 0 {
		return s.rawDIDCommV2[0].Accept, nil
	}

	return nil, fmt.Errorf("endpoint Accept not found")
}

// RoutingKeys is the DIDComm V2 RoutingKeys field of a service endpoint.
func (s *Endpoint) RoutingKeys() ([]string, error) {
	// TODO for now, returning RoutingKeys of first element. Add mechanism to fetch appropriate value.
	if len(s.rawDIDCommV2) > 0 {
		return s.rawDIDCommV2[0].RoutingKeys, nil
	}

	return nil, fmt.Errorf("endpoint RoutingKeys not found")
}

// Type return endpoint type.
func (s *Endpoint) Type() EndpointType {
	if len(s.rawDIDCommV2) > 0 {
		return DIDCommV2
	}

	if s.rawDIDCommV1 != "" {
		return DIDCommV1
	}

	return Generic
}

// MarshalJSON marshals the content of Endpoint into a valid JSON []byte. Order of data is:
// 1. DIDCommV2 format if found
// 2. DIDCommV1 format if found
// 3. DIDCore generic format if found
// 4. JSON "Null" as fallback.
func (s *Endpoint) MarshalJSON() ([]byte, error) {
	if len(s.rawDIDCommV2) > 0 {
		return json.Marshal(s.rawDIDCommV2)
	}

	if s.rawDIDCommV1 != "" {
		return []byte(fmt.Sprintf("%q", s.rawDIDCommV1)), nil
	}

	if s.rawObj != nil {
		return json.Marshal(s.rawObj)
	}

	// for existing connections, Endpoint can be empty, therefore don't fail marshalling here and
	// return JSON null value instead.
	return []byte("null"), nil
}

// UnmarshalJSON unmarshals data into Endpoint based on its format.
func (s *Endpoint) UnmarshalJSON(data []byte) error {
	s.rawDIDCommV2 = []DIDCommV2Endpoint{}
	if err := json.Unmarshal(data, &s.rawDIDCommV2); err == nil {
		s.rawDIDCommV1 = ""
		s.rawObj = nil

		return nil
	}

	if ok := isURL(string(data)); ok {
		s.rawDIDCommV1 = stripQuotes(string(data))
		s.rawDIDCommV2 = nil
		s.rawObj = nil

		return nil
	}

	if err := json.Unmarshal(data, &s.rawObj); err == nil {
		s.rawDIDCommV1 = ""
		s.rawDIDCommV2 = nil

		return nil
	}

	return fmt.Errorf("endpoint data is not supported")
}

func isURL(str string) bool {
	str = stripQuotes(str)

	u, err := url.Parse(str)

	return err == nil && u.Scheme != "" && u.Host != ""
}

func stripQuotes(str string) string {
	if len(str) > 0 {
		if str[0] == '"' {
			str = str[1:]
		}

		if str[len(str)-1] == '"' {
			str = str[:len(str)-1]
		}
	}

	return str
}
