# Instruction to run bdd tests

## Demonstration
- Two agents establish connection using did exchange protocol sdk (didexchange_e2e_sdk)
- Two agents establish connection using did exchange protocol rest api (didexchange_e2e_controller)
- Two agents establish connection using did exchange protocol sdk with public did in invitation (didexchange_public_dids)
- Resolve did document against [sidetree-mock](https://github.com/trustbloc/sidetree-mock)  (didresolver)


## Run all tests
Run all bdd tests using the following make target from project root directory.

`make bdd-test`

## Run specific bdd test
`make clean generate-test-keys agent-docker sample-webhook-docker`

Execute the following command inside test/bdd

`AGENT_LOG_LEVEL=#log_level# go test -run #name_of_test#`

Example
```bash
make clean generate-test-keys agent-docker sample-webhook-docker
cd test/bdd
AGENT_LOG_LEVEL=info go test -v -run didexchange_e2e_sdk
```
