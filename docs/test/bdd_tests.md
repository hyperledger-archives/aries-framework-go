# Run bdd tests

## Demonstration
- Two agents establish connection using did exchange protocol sdk (didexchange_e2e_sdk)
- Two agents establish connection using did exchange protocol rest api (didexchange_e2e_controller)
- Two agents establish connection using did exchange protocol sdk with public did in invitation (didexchange_public_dids)
- Resolve did document against [sidetree-mock](https://github.com/trustbloc/sidetree-mock)  (didresolver)


## Run all tests
Run all bdd tests using the following make target from project root directory.

`make bdd-test`

## Run aries-js-worker BDD tests

Run tests for [`aries-js-worker`](../../cmd/aries-js-worker) in the headless browser with:

```
make bdd-test-js
```

## Run specific aries-framework-go bdd tests
`make clean generate-test-keys agent-rest-docker sample-webhook-docker`

Execute the following command inside test/bdd

`AGENT_LOG_LEVEL=#log_level# go test -run #name_of_test#`

Example
```bash
make clean generate-test-keys agent-rest-docker sample-webhook-docker
cd test/bdd
AGENT_LOG_LEVEL=info go test -v -run didexchange_e2e_sdk
```

### Run tests in detached mode

If you're interested to start the docker containers manually and run parts of the bdd tests on your own as opposed
via the make target mentioned above, then do the following:

1. Navigate to test/bdd/fixtures

2. To start Alice and Bob agents and webhooks, go to `agent-rest` folder and run:
```shell script
(source .env && docker-compose down && NO_PROXY=* docker-compose up --force-recreate)
```
   
3. To start the Demo API hosts for Alice and Bob, open up a new terminal and go to `demo/openapi` folder and run the 
above command.

4. To start Sidetree Mock service, open up a new terminal go to `sidetree-mock` folder and run the same above command.

5. Once all the containers above have started, you are ready to run BDD tests manually.

6. To run the tests manually, in a new terminal, navigate to `tests/bdd` folder and run the same test command as mentioned in 
[Run specific bdd test](#Run-specific-bdd-test) section above by pre-pending the following environment variable:
```shell script
DISABLE_COMPOSITION=true
``` 
The tests will start executing and you will notice logs written to the containers created above depicting 
their activities and the test results shown in its own terminal created above.

