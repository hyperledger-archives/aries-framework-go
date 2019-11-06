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

func Test_isJWS(t *testing.T) {
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
			name: "empty third part",
			args: args{[]byte("empty third.part.")},
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
			name: "is JWS",
			args: args{[]byte(fmt.Sprintf("%s.%s.signature", jb64, jb64))},
			want: true,
		},
	}
	for i := range tests {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			if got := isJWS(tt.args.data); got != tt.want {
				t.Errorf("isJWS() = %v, want %v", got, tt.want)
			}
		})
	}
}
