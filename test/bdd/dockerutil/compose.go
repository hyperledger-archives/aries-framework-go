/*
Copyright IBM Corp. 2016 All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package dockerutil contains utils for working with docker.
//nolint:errorlint
package dockerutil

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	docker "github.com/fsouza/go-dockerclient"
)

const dockerComposeCommand = "docker-compose"

// Composition represents a docker-compose execution and management.
type Composition struct {
	DockerClient     *docker.Client
	APIContainers    []*docker.APIContainers
	ComposeFilesYaml string
	ProjectName      string
	Dir              string
	DockerHelper     DockerHelper
}

// NewComposition create a new Composition specifying the project name (for isolation) and the compose files.
func NewComposition(projectName, composeFilesYaml, dir string) (composition *Composition, err error) {
	errRetFunc := func() error {
		return fmt.Errorf("error creating new composition '%s' using compose yaml '%s':  %s",
			projectName, composeFilesYaml, err)
	}

	endpoint := "unix:///var/run/docker.sock"
	composition = &Composition{ComposeFilesYaml: composeFilesYaml, ProjectName: projectName, Dir: dir}

	if composition.DockerClient, err = docker.NewClient(endpoint); err != nil {
		return nil, errRetFunc()
	}

	if _, err = composition.issueCommand([]string{"up", "--force-recreate", "-d"}, dir); err != nil {
		return nil, errRetFunc()
	}

	composition.DockerHelper = NewDockerCmdlineHelper()

	// Now parse the current system
	return composition, nil
}

func parseComposeFilesArg(composeFileArgs string) []string {
	var args []string
	for _, f := range strings.Fields(composeFileArgs) {
		args = append(args, []string{"-f", f}...)
	}

	return args
}

func (c *Composition) getFileArgs() []string {
	return parseComposeFilesArg(c.ComposeFilesYaml)
}

// GetContainerIDs returns the container IDs for the composition
// (NOTE: does NOT include those defined outside composition, eg. chaincode containers).
func (c *Composition) GetContainerIDs(dir string) (containerIDs []string, err error) {
	var cmdOutput []byte

	if cmdOutput, err = c.issueCommand([]string{"ps", "-q"}, dir); err != nil {
		return nil, fmt.Errorf("error getting container IDs for project '%s':  %s", c.ProjectName, err)
	}

	containerIDs = splitDockerCommandResults(string(cmdOutput))

	return containerIDs, err
}

func (c *Composition) refreshContainerList() (err error) {
	var thisProjectsContainers []docker.APIContainers

	if thisProjectsContainers, err = c.DockerClient.ListContainers(
		docker.ListContainersOptions{
			All:     true,
			Filters: map[string][]string{"name": {c.ProjectName}},
		}); err != nil {
		return fmt.Errorf("error refreshing container list for project '%s':  %s", c.ProjectName, err)
	}

	c.APIContainers = make([]*docker.APIContainers, len(thisProjectsContainers))
	for i := 0; i < len(thisProjectsContainers); i++ {
		c.APIContainers[i] = &thisProjectsContainers[i]
	}

	return nil
}

func (c *Composition) issueCommand(args []string, dir string) (_ []byte, err error) {
	var cmdOut []byte

	errRetFunc := func() error {
		return fmt.Errorf("error issuing command to docker-compose with args '%s':  %s (%s)", args, err, string(cmdOut))
	}

	var cmdArgs []string
	cmdArgs = append(cmdArgs, c.getFileArgs()...)
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command(dockerComposeCommand, cmdArgs...) //nolint: gosec
	cmd.Dir = dir

	if cmdOut, err = cmd.CombinedOutput(); err != nil {
		return cmdOut, errRetFunc()
	}

	// Reparse Container list
	if err = c.refreshContainerList(); err != nil {
		return nil, errRetFunc()
	}

	return cmdOut, err
}

// Decompose decompose the composition.
// Will also remove any containers with the same ProjectName prefix (eg. chaincode containers).
func (c *Composition) Decompose(dir string) (output string, err error) {
	var outputBytes []byte

	_, err = c.issueCommand([]string{"stop"}, dir)
	if err != nil {
		log.Fatal(err)
	}

	outputBytes, err = c.issueCommand([]string{"rm", "-f"}, dir)
	// Now remove associated chaincode containers if any
	containerErr := c.DockerHelper.RemoveContainersWithNamePrefix(c.ProjectName)

	if containerErr != nil {
		log.Fatal(containerErr)
	}

	return string(outputBytes), err
}

// GenerateLogs to file.
func (c *Composition) GenerateLogs(dir, logName string) error {
	outputBytes, err := c.issueCommand([]string{"logs"}, dir)
	if err != nil {
		return err
	}

	// must use O_APPEND to append data; ioutil.WriteFile() overwrites data in the file.
	f, err := os.OpenFile("docker-compose.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}

	_, err = f.Write(outputBytes)
	if err1 := f.Close(); err1 != nil && err == nil {
		err = err1
	}

	return err
}

// GetAPIContainerForComposeService return the docker.APIContainers with the supplied composeService name.
func (c *Composition) GetAPIContainerForComposeService(
	composeService string) (apiContainer *docker.APIContainers, err error) {
	for _, apiContainer := range c.APIContainers {
		if currComposeService, ok := apiContainer.Labels["com.docker.compose.service"]; ok {
			if currComposeService == composeService {
				return apiContainer, nil
			}
		}
	}

	return nil, fmt.Errorf("could not find container with compose service '%s'", composeService)
}

// GetIPAddressForComposeService returns the IPAddress of the container with the supplied composeService name.
func (c *Composition) GetIPAddressForComposeService(composeService string) (ipAddress string, err error) {
	errRetFunc := func() error {
		return fmt.Errorf("error getting IPAddress for compose service '%s':  %s", composeService, err)
	}

	var apiContainer *docker.APIContainers

	if apiContainer, err = c.GetAPIContainerForComposeService(composeService); err != nil {
		return "", errRetFunc()
	}

	// Now get the IPAddress
	return apiContainer.Networks.Networks["bridge"].IPAddress, nil
}

// GenerateBytesUUID returns a UUID based on RFC 4122 returning the generated bytes.
func GenerateBytesUUID() []byte {
	uuid := make([]byte, 16)

	_, err := io.ReadFull(rand.Reader, uuid)
	if err != nil {
		panic(fmt.Sprintf("error generating UUID: %s", err))
	}

	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80 //nolint:gomnd

	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40 //nolint:gomnd

	return uuid
}
