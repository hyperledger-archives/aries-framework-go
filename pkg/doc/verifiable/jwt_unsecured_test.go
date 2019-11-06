/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// nolint:gochecknoglobals
var (
	joseHeaders   = map[string]string{"alg": "none"}
	jwtClaims     = map[string]interface{}{"sub": "user123", "productIds": []int{1, 2}}
	jwtSerialized = "eyJhbGciOiJub25lIn0.eyJwcm9kdWN0SWRzIjpbMSwyXSwic3ViIjoidXNlcjEyMyJ9."
)

func TestMarshalUnsecuredJWT(t *testing.T) {
	t.Run("serialize unsecured JWT", func(t *testing.T) {
		unsecuredJWT, err := marshalUnsecuredJWT(joseHeaders, jwtClaims)
		require.NoError(t, err)
		require.Equal(t, jwtSerialized, unsecuredJWT)
	})

	t.Run("incorrect JWT payload", func(t *testing.T) {
		unmarshallable := make(chan bool)

		_, err := marshalUnsecuredJWT(joseHeaders, unmarshallable)
		require.Error(t, err)
	})
}

func TestUnmarshalUnsecuredJWT(t *testing.T) {
	jwtClaimsBytes, serError := json.Marshal(jwtClaims)
	require.NoError(t, serError)

	notBase64 := "[not base64]"
	notJSON := base64.RawURLEncoding.EncodeToString([]byte("Not JSON!"))

	t.Run("decodes unsecured JWT", func(t *testing.T) {
		decodedHeaders, decodedClaims, err := unmarshalUnsecuredJWT([]byte(jwtSerialized))
		require.NoError(t, err)
		require.Equal(t, joseHeaders, decodedHeaders)
		require.Equal(t, jwtClaimsBytes, decodedClaims)
	})

	t.Run("rejects serialized JWT of invalid format", func(t *testing.T) {
		_, _, err := unmarshalUnsecuredJWT([]byte("invalid JWT"))
		require.EqualError(t, err, "JWT format must have three parts")
	})

	t.Run("rejects signed JWT", func(t *testing.T) {
		_, _, err := unmarshalUnsecuredJWT([]byte("headers.payload.signature"))
		require.EqualError(t, err, "unsecured JWT must have empty signature part")
	})

	t.Run("rejects serialized JWT headers not in base64 format", func(t *testing.T) {
		invalidJWT := fmt.Sprintf("%s.eyJwcm9kdWN0SWRzIjpbMSwyXSwic3ViIjoidXNlcjEyMyJ9.", notBase64)
		_, _, err := unmarshalUnsecuredJWT([]byte(invalidJWT))
		require.Error(t, err)
	})

	t.Run("rejects JWT headers which are not JSON", func(t *testing.T) {
		invalidJWT := fmt.Sprintf("%s.eyJwcm9kdWN0SWRzIjpbMSwyXSwic3ViIjoidXNlcjEyMyJ9.", notJSON)
		_, _, err := unmarshalUnsecuredJWT([]byte(invalidJWT))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal JSON-based JOSE headers")
	})

	t.Run("rejects serialized JWT claims not in base64 format", func(t *testing.T) {
		invalidJWT := fmt.Sprintf("eyJhbGciOiJub25lIn0.%s.", notBase64)
		_, _, err := unmarshalUnsecuredJWT([]byte(invalidJWT))
		require.Error(t, err)
	})

	t.Run("rejects JWT claims which are not JSON", func(t *testing.T) {
		invalidJWT := fmt.Sprintf("eyJhbGciOiJub25lIn0.%s.", notJSON)
		_, _, err := unmarshalUnsecuredJWT([]byte(invalidJWT))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal JSON-based JWT claims")
	})
}

func Test_isJWTUnsecured(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	j, err := json.Marshal(map[string]string{"alg": "none"})
	require.NoError(t, err)
	jb64 := base64.RawURLEncoding.EncodeToString(j)

	type args struct {
		data []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "two parts only",
			args: args{[]byte("two parts.only")},
			want: false,
		},
		{
			name: "not empty third part",
			args: args{[]byte("third.part.not-empty")},
			want: false,
		},
		{
			name: "part 1 is not base64 decoded",
			args: args{[]byte("not base64.part2.part3")},
			want: false,
		},
		{
			name: "part 1 is not JSON",
			args: args{[]byte(fmt.Sprintf("%s.part2.part3", b64))},
			want: false,
		},
		{
			name: "part 2 is not base64 decoded",
			args: args{[]byte(fmt.Sprintf("%s.not base64.part3", jb64))},
			want: false,
		},
		{
			name: "part 2 is not JSON",
			args: args{[]byte(fmt.Sprintf("%s.%s.part3", jb64, b64))},
			want: false,
		},
		{
			name: "is JWT unsecured",
			args: args{[]byte(fmt.Sprintf("%s.%s.", jb64, jb64))},
			want: true,
		},
	}
	for i := range tests {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			if got := isJWTUnsecured(tt.args.data); got != tt.want {
				t.Errorf("isJWTUnsecured() = %v, want %v", got, tt.want)
			}
		})
	}
}
