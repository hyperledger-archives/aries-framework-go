# JSON-LD Context API

The concept of **JSON-LD Context** is described in JSON-LD spec [here](https://www.w3.org/TR/json-ld11/#the-context).

In Aries, contexts are used by a JSON-LD processor during operations that involve processing JSON-LD documents (signing
credentials, adding linked data proofs, etc.).

JSON-LD processor uses [document loader](https://www.w3.org/TR/json-ld11/#loading-documents) for resolving contexts.
Document loader is one of the dependencies of Aries with a default implementation that supports storing contexts in the
underlying storage. The custom document loader can be set using `WithJSONLDDocumentLoader()` option during construction
of the Aries instance ([custom-document-loader]).

## Default document loader

The default document loader (`ld.DocumentLoader` from `pkg/doc/ld`) preloads [embedded] contexts as part of its
initialization logic. Additional contexts can be added using `WithExtraContexts()` option:

```go
ld.NewDocumentLoader(provider, ld.WithExtraContexts())
```

### Resolving contexts from the remote URLs

By default, if the context is not found in the underlying storage, an error is returned. For resolving any context,
document loader can be initialized with a loader that supports fetching from the remote URL. For that purpose, the
document loader that comes with the `github.com/piprate/json-gold` package might be helpful.
Use `WithRemoteDocumentLoader()` option to specify the one:

```go
ld.NewDocumentLoader(provider,
    ld.WithRemoteDocumentLoader(jsonld.NewDefaultDocumentLoader(http.DefaultClient)))
```

:warning: Fetching contexts from the remote URLs might affect performance significantly.

## Adding contexts dynamically

Contexts can be added to the Aries agent in runtime via REST API:

```
POST /ld/context

[
  {
    "content": {},
    "documentURL": "string",
    "url": "string"
  }
]
```

or by using SDK client:

```go
ld.NewClient(provider).AddContexts()
```

Aries JS worker supports adding new contexts with `ld.addContexts()` method. Check [js-add-contexts].

## Remote context provider

Contexts that are hosted on a remote server can be added to the Aries instance via remote context provider. Use
`WithRemoteProvider()` option of the document loader or REST/JS API to add a new remote provider to the agent.

```go
ld.NewDocumentLoader(provider, ld.WithRemoteProvider())
```

Environment variable `ARIESD_CONTEXT_PROVIDER_URL` (or `context-provider-url` flag) allows setting up multiple remote
context providers for the Aries REST agent. In case of the Aries JS worker the `context-provider-url` option is used.

### Setting up remote server for hosting contexts

The default implementation of remote context provider (`remote.Provider` from `pkg/doc/ldcontext/remote`) makes request
to the endpoint passed to the constructor and expects response in the following format:

```json
{
  "documents": [
    {
      "url": "https://www.w3.org/2018/credentials/examples/v1",
      "content": {}
    },
    {
      "url": "https://www.w3.org/ns/odrl.jsonld",
      "content": {}
    }
  ]
}
```

Refer to BDD tests for examples of setting up file servers with JSON-LD contexts ([js-bdd], [rest-bdd]).

### Remote context provider API

Remote context providers can be added, refreshed and deleted using REST API, SDK client (`pkg/client/ld`) or JS worker's
`ld` methods. Check [OpenAPI specification](./rest/openapi_spec.md), section `ld`, for REST API details.

---
[custom-document-loader]: https://github.com/hyperledger/aries-framework-go/blob/5e24fee3adbaf5a462c8951f0e92cada81cd288b/test/bdd/agent/agent_sdk_steps.go#L75
[embedded]: https://github.com/hyperledger/aries-framework-go/blob/5e24fee3adbaf5a462c8951f0e92cada81cd288b/pkg/doc/ldcontext/embed/embed_contexts.go#L48
[js-add-contexts]: https://github.com/hyperledger/aries-framework-go/blob/5e24fee3adbaf5a462c8951f0e92cada81cd288b/test/aries-js-worker/test/ld/ld.js#L55
[js-bdd]: https://github.com/hyperledger/aries-framework-go/blob/5e24fee3adbaf5a462c8951f0e92cada81cd288b/test/aries-js-worker/fixtures/docker-compose.yml#L95
[rest-bdd]: https://github.com/hyperledger/aries-framework-go/blob/5e24fee3adbaf5a462c8951f0e92cada81cd288b/test/bdd/fixtures/agent-rest/docker-compose.yml#L313
