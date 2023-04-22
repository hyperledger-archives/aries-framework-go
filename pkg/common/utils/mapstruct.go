/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/mitchellh/mapstructure"
)

func JsonNumberToJsonDate() mapstructure.DecodeHookFuncType {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{},
	) (interface{}, error) {
		if f.String() != "json.Number" || !strings.Contains("jwt.NumericDate", t.String()) {
			return data, nil
		}

		parsedFloat, err := strconv.ParseFloat(fmt.Sprint(data), 64)
		if err != nil {
			return nil, err
		}

		date := jwt.NewNumericDate(time.Unix(int64(parsedFloat), 0))

		if t.String() == "jwt.NumericDate" {
			return date, nil
		}
		return &date, nil
	}
}
