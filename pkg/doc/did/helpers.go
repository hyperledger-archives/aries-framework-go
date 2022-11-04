/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

// ContextCleanup performs non-intrusive cleanup of the given context by
// converting `[]string(nil)` and `[]interface{}(nil)` to the empty string, and
// converting `[]interface{}` to `[]string` if it contains only string values.
// This will NOT change string arrays into single strings, even when they contain
// only a single string.
func ContextCleanup(context Context) Context {
	context = ContextCopy(context)

	switch ctx := context.(type) {
	case string:
		return ctx
	case []string:
		if len(ctx) == 0 {
			return []string{""}
		}

		return ctx
	case []interface{}:
		if len(ctx) == 0 {
			return ""
		}

		var newContext []string

		for _, item := range ctx {
			strVal, ok := item.(string)
			if !ok {
				return ctx
			}

			newContext = append(newContext, strVal)
		}

		return newContext
	}

	return context
}

// ContextCopy create a deep copy of the given context. This is used to prevent
// unintentional mutations of `Context` instances which are passed to functions
// that modify and return updated values, e.g., `parseContext()`.
func ContextCopy(context Context) Context {
	switch ctx := context.(type) {
	case string:
		return ctx
	case []string:
		var newContext []string
		newContext = append(newContext, ctx...)

		return newContext
	case []interface{}:
		var newContext []interface{}

		for _, v := range ctx {
			switch value := v.(type) {
			case string:
				newContext = append(newContext, value)
			case map[string]interface{}:
				newValue := map[string]interface{}{}
				for k, v := range value {
					newValue[k] = v
				}

				newContext = append(newContext, newValue)
			}
		}

		return newContext
	}

	return context
}

// ContextPeekString returns the first string element in `context`, which
// identifies the DID JSON-LD schema in use. This is generally useful to
// branch based on the version of the DID schema.
func ContextPeekString(context Context) (string, bool) {
	switch ctx := context.(type) {
	case string:
		if len(ctx) > 0 {
			return ctx, true
		}
	case []string:
		if len(ctx) > 0 {
			return ctx[0], true
		}
	case []interface{}:
		if len(ctx) > 0 {
			if strval, ok := ctx[0].(string); ok {
				return strval, true
			}
		}
	}

	return "", false
}

// ContextContainsString returns true if the given Context contains the given
// context string. Strings nested inside maps are not checked.
func ContextContainsString(context Context, contextString string) bool {
	// Extract all string values from context
	var have []string
	switch ctx := context.(type) {
	case string:
		have = append(have, ctx)
	case []string:
		have = append(have, ctx...)
	case []interface{}:
		for _, val := range ctx {
			if strval, ok := val.(string); ok {
				have = append(have, strval)
			}
		}
	}

	// Look for desired string in extracted values
	for _, item := range have {
		if item == contextString {
			return true
		}
	}

	return false
}

// LookupService returns the service from the given DIDDoc matching the given service type.
func LookupService(didDoc *Doc, serviceType string) (*Service, bool) {
	const notFound = -1
	index := notFound

	for i := range didDoc.Service {
		if didDoc.Service[i].Type == serviceType {
			if index == notFound || comparePriority(didDoc.Service[index].Priority, didDoc.Service[i].Priority) {
				index = i
			}
		}
	}

	if index == notFound {
		return nil, false
	}

	return &didDoc.Service[index], true
}

func comparePriority(v1, v2 interface{}) bool {
	// expecting positive integers plus zero; otherwise cannot compare priority
	intV1, okV1 := v1.(int)
	intV2, okV2 := v2.(int)

	if okV1 && okV2 {
		return intV1 > intV2
	}

	if !okV1 && !okV2 {
		return false
	}

	return !okV1
}

// LookupDIDCommRecipientKeys gets the DIDComm recipient keys from the did doc which match the given parameters.
// DIDComm recipient keys are encoded as did:key identifiers.
// See:
// - https://github.com/hyperledger/aries-rfcs/blob/master/features/0067-didcomm-diddoc-conventions/README.md
// - https://github.com/hyperledger/aries-rfcs/blob/master/features/0360-use-did-key/README.md
func LookupDIDCommRecipientKeys(didDoc *Doc) ([]string, bool) {
	didCommService, ok := LookupService(didDoc, "did-communication")
	if !ok {
		return nil, false
	}

	if len(didCommService.RecipientKeys) == 0 {
		return nil, false
	}

	return didCommService.RecipientKeys, true
}

// LookupPublicKey returns the public key with the given id from the given DID Doc.
func LookupPublicKey(id string, didDoc *Doc) (*VerificationMethod, bool) {
	for _, key := range didDoc.VerificationMethod {
		if key.ID == id {
			return &key, true
		}
	}

	return nil, false
}
