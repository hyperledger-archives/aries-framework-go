/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/DATA-DOG/godog"
	"github.com/go-openapi/swag"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-node/models"

	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
	"github.com/hyperledger/aries-framework-go/test/bdd/dockerutil"
)

const (
	SideTreeURL     = "${SIDETREE_URL}"
	DIDDocPath      = "${DID_DOC_PATH}"
	sha2_256        = 18
	didDocNamespace = "did:sidetree:"
	maxRetry        = 10
)

// DIDResolverSteps
type DIDResolverSteps struct {
	bddContext       *Context
	reqEncodedDIDDoc string
	resp             *httpRespone
}

// NewDIDResolverSteps
func NewDIDResolverSteps(context *Context) *DIDResolverSteps {
	return &DIDResolverSteps{bddContext: context}
}

func (d *DIDResolverSteps) createDIDDocument(agentID string, sideTreeURL string) error {
	req := newCreateRequest(createSidetreeDoc(d.bddContext.AgentCtx[agentID]))
	d.reqEncodedDIDDoc = swag.StringValue(req.Payload)
	resp, err := sendRequest(d.bddContext.Args[sideTreeURL], req)
	if err != nil {
		return fmt.Errorf("failed to create public DID document: %s", d.resp.errorMsg)
	}

	doc, err := diddoc.ParseDocument(resp.payload)
	if err != nil {
		return fmt.Errorf("failed to parse public DID document: %s", err)
	}

	d.bddContext.PublicDIDs[agentID] = doc
	return nil
}

func (d *DIDResolverSteps) createDIDDocumentFromFile(sideTreeURL, didDocumentPath string) error {
	req := newCreateRequest(didDocFromFile(d.bddContext.Args[didDocumentPath]))
	d.reqEncodedDIDDoc = swag.StringValue(req.Payload)
	var err error
	d.resp, err = sendRequest(d.bddContext.Args[sideTreeURL], req)
	return err
}

func (d *DIDResolverSteps) checkSuccessResp(msg string) error {
	if d.resp.errorMsg != "" {
		return fmt.Errorf("error resp %s", d.resp.errorMsg)
	}

	if msg == "#didID" {
		didID, err := docutil.CalculateID(didDocNamespace, d.reqEncodedDIDDoc, sha2_256)
		if err != nil {
			return err
		}
		msg = strings.Replace(msg, "#didID", didID, -1)
	}
	logger.Debugf("check success resp %s contain %s", string(d.resp.payload), msg)
	if !strings.Contains(string(d.resp.payload), msg) {
		return fmt.Errorf("success resp %s doesn't contain %s", d.resp.payload, msg)
	}
	return nil
}

func (d *DIDResolverSteps) resolveDID(agentID string) error {
	didID, err := docutil.CalculateID(didDocNamespace, d.reqEncodedDIDDoc, sha2_256)
	if err != nil {
		return err
	}

	doc, err := resolveDID(d.bddContext.AgentCtx[agentID].DIDResolver(), didID, maxRetry)
	if err != nil {
		return err
	}

	if doc.ID != didID {
		return fmt.Errorf("resolved did ID %s not equal to %s", doc.ID, didID)
	}
	return nil
}

func newCreateRequest(doc *document.Document) *models.Request {
	payload := encodeDidDocument(doc)
	return &models.Request{
		Header: &models.Header{
			Operation: models.OperationTypeCreate, Alg: swag.String(""), Kid: swag.String("")},
		Payload:   swag.String(payload),
		Signature: swag.String("")}
}

func didDocFromFile(didDocumentPath string) *document.Document {
	r, _ := os.Open(didDocumentPath)
	data, _ := ioutil.ReadAll(r)
	doc, _ := document.FromBytes(data)
	// add new key to make the document unique
	doc["unique"] = generateUUID()
	return &doc
}
func encodeDidDocument(doc *document.Document) string {
	bytes, _ := doc.Bytes()
	return base64.URLEncoding.EncodeToString(bytes)
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
func sendRequest(url string, req *models.Request) (*httpRespone, error) {
	resp, err := sendHTTPRequest(url, req)
	if err != nil {
		return nil, err
	}
	return handleHttpResp(resp)
}

func handleHttpResp(resp *http.Response) (*httpRespone, error) {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body failed: %w", err)
	}
	if status := resp.StatusCode; status != http.StatusOK {
		return &httpRespone{errorMsg: string(body)}, nil
	}
	return &httpRespone{payload: body}, nil
}

func sendHTTPRequest(url string, req *models.Request) (*http.Response, error) {
	client := &http.Client{}
	b, err := req.MarshalBinary()
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

func createSidetreeDoc(ctx *context.Provider) *document.Document {
	_, pubVerKey, err := ctx.CryptoWallet().CreateKeySet()
	if err != nil {
		panic(err)
	}

	pubKey := diddoc.PublicKey{
		ID:         "#keys-1",
		Type:       "Ed25519VerificationKey2018",
		Controller: "controller",
		Value:      []byte(pubVerKey),
	}

	services := []diddoc.Service{
		{
			ID:              "#endpoint-1",
			Type:            "did-communication",
			ServiceEndpoint: ctx.InboundTransportEndpoint(),
		},
	}

	didDoc := &diddoc.Doc{
		Context:   []string{diddoc.Context},
		PublicKey: []diddoc.PublicKey{pubKey},
		Service:   services,
	}

	bytes, err := didDoc.JSONBytes()
	if err != nil {
		panic(err)
	}

	doc, err := document.FromBytes(bytes)
	if err != nil {
		panic(err)
	}

	return &doc
}

func resolveDID(resolver didresolver.Resolver, did string, maxRetry int) (*diddoc.Doc, error) {
	var err error
	var doc *diddoc.Doc
	for i := 1; i <= maxRetry; i++ {
		doc, err = resolver.Resolve(did)
		if err == nil || !strings.Contains(err.Error(), "DID does not exist") {
			return doc, err
		}

		time.Sleep(1 * time.Second)
		logger.Debugf("Waiting for public did to be published in sidtree: %d second(s)\n", i)
	}

	return doc, err
}

// RegisterSteps registers did exchange steps
func (d *DIDResolverSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^client sends request to sidetree "([^"]*)" for create DID document "([^"]*)"`, d.createDIDDocumentFromFile)
	s.Step(`^check success response contains "([^"]*)"$`, d.checkSuccessResp)
	s.Step(`^"([^"]*)" creates public DID using sidetree "([^"]*)"`, d.createDIDDocument)
	s.Step(`^"([^"]*)" agent sucessfully resolves DID document$`, d.resolveDID)
}
