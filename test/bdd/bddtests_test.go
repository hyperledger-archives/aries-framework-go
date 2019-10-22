/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/godog"
	"github.com/hyperledger/aries-framework-go/test/bdd/dockerutil"
)

var composition []*dockerutil.Composition
var composeFiles = []string{"./fixtures/sidetree-node", "./fixtures/agent"}

func TestMain(m *testing.M) {

	// default is to run all tests with tag @all
	tags := "all"
	flag.Parse()
	cmdTags := flag.CommandLine.Lookup("test.run")
	if cmdTags != nil && cmdTags.Value != nil && cmdTags.Value.String() != "" {
		tags = cmdTags.Value.String()
	}

	initBDDConfig()

	status := godog.RunWithOptions("godogs", func(s *godog.Suite) {
		s.BeforeSuite(func() {

			if os.Getenv("DISABLE_COMPOSITION") != "true" {

				// Need a unique name, but docker does not allow '-' in names
				composeProjectName := strings.Replace(generateUUID(), "-", "", -1)

				for _, v := range composeFiles {
					newComposition, err := dockerutil.NewComposition(composeProjectName, "docker-compose.yml", v)
					if err != nil {
						panic(fmt.Sprintf("Error composing system in BDD context: %s", err))
					}
					composition = append(composition, newComposition)
				}
				fmt.Println("docker-compose up ... waiting for containers to start ...")
				testSleep := 15
				if os.Getenv("TEST_SLEEP") != "" {
					testSleep, _ = strconv.Atoi(os.Getenv("TEST_SLEEP"))
				}
				fmt.Printf("*** testSleep=%d", testSleep)
				time.Sleep(time.Second * time.Duration(testSleep))
			}

		})
		s.AfterSuite(func() {
			for _, c := range composition {
				if c != nil {
					if err := c.GenerateLogs(c.Dir, c.ProjectName+".log"); err != nil {
						panic(err)
					}
					if _, err := c.Decompose(c.Dir); err != nil {
						panic(err)
					}
				}
			}
		})
		FeatureContext(s)
	}, godog.Options{
		Tags:          tags,
		Format:        "progress",
		Paths:         []string{"features"},
		Randomize:     time.Now().UTC().UnixNano(), // randomize scenario execution order
		Strict:        true,
		StopOnFailure: true,
	})

	if st := m.Run(); st > status {
		status = st
	}
	os.Exit(status)
}

func FeatureContext(s *godog.Suite) {

	context, err := NewContext()
	if err != nil {
		panic(fmt.Sprintf("Error returned from NewBDDContext: %s", err))
	}

	// set dynamic args
	context.Args[SideTreeURL] = "http://localhost:48326/.sidetree/document"
	context.Args[DIDDocPath] = "fixtures/sidetree-node/config/didDocument.json"

	// alice agent container configuration
	context.Args[AliceAgentHost] = "alice.agent.example.com"
	context.Args[AliceAgentPort] = "8081"
	context.Args[AliceAgentController] = "http://localhost:8082"
	context.Args[AliceAgentWebhook] = "http://localhost:8083/sample"

	// bob agent container configuration
	context.Args[BobAgentHost] = "bob.agent.example.com"
	context.Args[BobAgentPort] = "9081"
	context.Args[BobAgentController] = "http://localhost:9082"
	context.Args[BobAgentWebhook] = "http://localhost:9083/sample"

	// Context is shared between tests
	NewAgentSDKSteps(context).RegisterSteps(s)
	NewAgentControllerSteps(context).RegisterSteps(s)
	NewDIDExchangeSteps(context).RegisterSteps(s)
	NewDIDResolverSteps(context).RegisterSteps(s)

}

func initBDDConfig() {
}
