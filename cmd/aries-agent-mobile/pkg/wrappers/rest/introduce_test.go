package rest

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers"
)

type mockHTTPClient struct {
	data string
}

func (client *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	r := ioutil.NopCloser(bytes.NewReader([]byte(client.data)))

	return &http.Response{
		StatusCode: 200,
		Body:       r,
	}, nil
}

func TestIntroduceREST_Actions(t *testing.T) {
	t.Run("test it performs an actions request", func(t *testing.T) {
		a := NewAries()
		ic, err := a.GetIntroduceController()
		require.NoError(t, err)
		require.NotNil(t, ic)

		mockResponse := `{"actions":[{"PIID":"ID1","Msg":null,"MyDID":"","TheirDID":""},{"PIID":"ID2","Msg":null,"MyDID":"","TheirDID":""}]}` //nolint:lll

		client := mockHTTPClient{data: mockResponse}
		i, ok := ic.(*IntroduceREST)
		require.Equal(t, ok, true)
		i.httpClient = &client

		req := &wrappers.IntroduceActionsRequest{
			URL:   "",
			Token: "",
		}
		resp := i.Actions(req)
		require.NotNil(t, resp)

		require.Equal(t, resp.ActionsResponse, mockResponse)
	})
}
