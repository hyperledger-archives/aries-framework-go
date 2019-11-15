/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didresolver

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/DATA-DOG/godog"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/test/bdd/dockerutil"
	bddctx "github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

const (
	sha2_256        = 18
	didDocNamespace = "did:sidetree:"
	maxRetry        = 10
)

var logger = log.New("aries-framework/didresolver-tests")

// Steps for DID resolver tests
type Steps struct {
	bddContext       *bddctx.BDDContext
	reqEncodedDIDDoc string
	resp             *httpRespone
}

// NewDIDResolverSteps returns new steps for DID resolver tests
func NewDIDResolverSteps(ctx *bddctx.BDDContext) *Steps {
	return &Steps{bddContext: ctx}
}

func (d *Steps) createDIDDocument(agentID, sideTreeURL string) error {
	sideTreeDoc, err := createSidetreeDoc(d.bddContext.AgentCtx[agentID])
	if err != nil {
		return err
	}

	req := newCreateRequest(sideTreeDoc)
	d.reqEncodedDIDDoc = req.Payload

	resp, err := sendRequest(d.bddContext.Args[sideTreeURL], req)
	if err != nil {
		return fmt.Errorf("failed to create public DID document: %w", err)
	}

	doc, err := diddoc.ParseDocument(resp.payload)
	if err != nil {
		return fmt.Errorf("failed to parse public DID document: %s", err)
	}

	d.bddContext.PublicDIDs[agentID] = doc

	return nil
}

func (d *Steps) createDIDDocumentFromFile(sideTreeURL, didDocumentPath string) error {
	req := newCreateRequest(d.didDocFromFile(didDocumentPath))
	d.reqEncodedDIDDoc = req.Payload

	var err error
	d.resp, err = sendRequest(d.bddContext.Args[sideTreeURL], req)

	return err
}

func (d *Steps) checkSuccessResp(msg string) error {
	if d.resp.errorMsg != "" {
		return fmt.Errorf("error resp %s", d.resp.errorMsg)
	}

	if msg == "#didID" {
		didID, err := docutil.CalculateID(didDocNamespace, d.reqEncodedDIDDoc, sha2_256)
		if err != nil {
			return err
		}

		msg = strings.ReplaceAll(msg, "#didID", didID)
	}

	logger.Debugf("check success resp %s contain %s", string(d.resp.payload), msg)

	if !strings.Contains(string(d.resp.payload), msg) {
		return fmt.Errorf("success resp %s doesn't contain %s", d.resp.payload, msg)
	}

	return nil
}

func (d *Steps) resolveDID(agentID string) error {
	didID, err := docutil.CalculateID(didDocNamespace, d.reqEncodedDIDDoc, sha2_256)
	if err != nil {
		return err
	}

	doc, err := resolveDID(d.bddContext.AgentCtx[agentID].VDRIRegistry(), didID, maxRetry)
	if err != nil {
		return err
	}

	if doc.ID != didID {
		return fmt.Errorf("resolved did ID %s not equal to %s", doc.ID, didID)
	}

	return nil
}

func (d *Steps) didDocFromFile(didDocumentPath string) *document.Document {
	r, err := os.Open(d.bddContext.Args[didDocumentPath])
	if err != nil {
		logger.Errorf("Failed to open document, %s", err)
	}

	data, err := ioutil.ReadAll(r)
	if err != nil {
		logger.Errorf("Failed to read document, %s", err)
	}

	doc, err := document.FromBytes(data)
	if err != nil {
		logger.Errorf("Failed to get bytes from document, %s", err)
	}

	// add new key to make the document unique
	doc["unique"] = generateUUID()

	return &doc
}

func newCreateRequest(doc *document.Document) *model.Request {
	payload := encodeDidDocument(doc)

	return &model.Request{
		Header: &model.Header{
			Operation: model.OperationTypeCreate, Alg: "", Kid: ""},
		Payload:   payload,
		Signature: ""}
}

func encodeDidDocument(doc *document.Document) string {
	b, err := doc.Bytes()
	if err != nil {
		logger.Errorf("Failed to get bytes from document, %s", err)
	}

	return base64.URLEncoding.EncodeToString(b)
}

// generateUUID returns a UUID based on RFC 4122
func generateUUID() string {
	id := dockerutil.GenerateBytesUUID()
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:])
}

type httpRespone struct {
	payload  []byte
	errorMsg string
}

// sendRequest sends a regular POST request to the sidetree-node
// - If post request has operation "create" then return sidetree document else no response
func sendRequest(url string, req *model.Request) (*httpRespone, error) {
	resp, err := sendHTTPRequest(url, req)
	if err != nil {
		return nil, err
	}

	return handleHTTPResp(resp)
}

func handleHTTPResp(resp *http.Response) (*httpRespone, error) {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body failed: %w", err)
	}

	if status := resp.StatusCode; status != http.StatusOK {
		return &httpRespone{errorMsg: string(body)}, nil
	}

	return &httpRespone{payload: body}, nil
}

func sendHTTPRequest(url string, req *model.Request) (*http.Response, error) {
	client := &http.Client{}

	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")

	return client.Do(httpReq)
}

func createSidetreeDoc(ctx *context.Provider) (*document.Document, error) {
	_, pubVerKey, err := ctx.KMS().CreateKeySet()
	if err != nil {
		return nil, err
	}

	pubKey := diddoc.PublicKey{
		ID:         "#key-1",
		Type:       "Ed25519VerificationKey2018",
		Controller: "controller",
		Value:      []byte(pubVerKey),
	}

	services := []diddoc.Service{
		{
			ID:              "#endpoint-1",
			Type:            "did-communication",
			ServiceEndpoint: ctx.InboundTransportEndpoint(),
			RecipientKeys:   []string{pubKey.ID},
			Priority:        0,
		},
	}

	didDoc := &diddoc.Doc{
		Context:   []string{diddoc.Context},
		PublicKey: []diddoc.PublicKey{pubKey},
		Service:   services,
	}

	b, err := didDoc.JSONBytes()
	if err != nil {
		return nil, err
	}

	doc, err := document.FromBytes(b)
	if err != nil {
		return nil, err
	}

	return &doc, nil
}

func resolveDID(vdriRegistry vdriapi.Registry, did string, maxRetry int) (*diddoc.Doc, error) {
	var doc *diddoc.Doc

	var err error
	for i := 1; i <= maxRetry; i++ {
		doc, err = vdriRegistry.Resolve(did)
		if err == nil || !strings.Contains(err.Error(), "DID does not exist") {
			return doc, err
		}

		time.Sleep(1 * time.Second)
		logger.Debugf("Waiting for public did to be published in sidtree: %d second(s)\n", i)
	}

	return doc, err
}

// RegisterSteps registers did exchange steps
func (d *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^client sends request to sidetree "([^"]*)" for create DID document "([^"]*)"`, d.createDIDDocumentFromFile)
	s.Step(`^check success response contains "([^"]*)"$`, d.checkSuccessResp)
	s.Step(`^"([^"]*)" creates public DID using sidetree "([^"]*)"`, d.createDIDDocument)
	s.Step(`^"([^"]*)" agent successfully resolves DID document$`, d.resolveDID)
}
