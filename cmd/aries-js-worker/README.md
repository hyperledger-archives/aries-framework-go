# Aries JS Worker

Aries Framework Go via Javascript.

## Build it

To build you will need:

* Go 1.16.x
* npm 6.13.x
* Node.JS 12.14.x
* bash

Run `npm install` in this directory. The output bundles will be placed in `dist/`.

## Usage

> Note: the API is in the very early stages of development and is still subject to a few changes.

### Entrypoints

`aries-js-worker` has several entrypoints tailored to the environment and needs:

* `dist/node/aries.js`: for use in node.js
* `dist/web/aries.js`: for use in the browser
* `dist/rest/aries.js`: for use in any environment but relying on an external
  [REST controller API server](https://github.com/hyperledger/aries-framework-go/blob/master/docs/rest/README.md)
  instead of the bundled webassembly module.

### Snippet

**Example:** accept a did-exchange invitation:

```js
// in the browser

const aries = await new Aries.Framework({
    assetsPath: "/public/dist/assets",
    "agent-default-label": "dem-js-agent",
    "http-resolver-url": [],
    "auto-accept": true,
    "outbound-transport": ["ws", "http"],
    "transport-return-route": "all",
    "log-level": "debug"
})

// sample invitation
const invitation = {
    "@id":"4d26ad47-c71b-4e2e-9358-0a76f7fa77e4",
    "@type":"https://didcomm.org/didexchange/1.0/invitation",
    "label":"demo-js-agent",
    "recipientKeys":["7rADm5sA9FHB4enuYXj6PJZDAm1JcesKmbtx7Qh8YZrg"],
    "serviceEndpoint":"routing:endpoint"
};

// listen for connection 'received' notification
aries.startNotifier(notice => {
    const event = notice.payload
    if (event.Type === "post_state") {
        // accept invitation
        aries.didexchange.acceptInvitation(event.Properties.connectionID)
    }
}, ["didexchange_states"])
// receive invitation
aries.didexchange.receiveInvitation(invitation)

// listen for connection 'completed' notification
aries.startNotifier(notice => {
    const event = notice.payload
    if (event.StateID === "completed" && event.Type === "post_state") {
        console.log("connection completed!")
    }

}, ["didexchange_states"])

// release resources
aries.destroy()
```

### Browser

Note: make sure the assets are [served correctly](#important---serving-the-assets).

Source `aries.js` in your `<script>` tag:

```html
<script src="dist/web/aries.js"></script>
```

Then initialize your aries instance:

```js
const aries = await new Aries.Framework({
    assetsPath: "/path/serving/the/assets",
    "agent-default-label": "dem-js-agent",
    "http-resolver-url": [],
    "auto-accept": true,
    "outbound-transport": ["ws", "http"],
    "transport-return-route": "all",
    "log-level": "debug"
})
```

### REST

Note: make sure the assets are [served correctly](#important---serving-the-assets) if you're running aries in the browser.

Assuming you're in the browser, source `aries.js` in your `<script>` tag:

```html
<script src="dist/rest/aries.js"></script>
```

Then initialize your aries instance:

```js
const aries = await new Aries.Framework({
    assetsPath: "/path/serving/the/assets", // still required for assets other than the wasm
    "agent-rest-url": "http://controller.api.example.com", // REST controller URL of the agent
    "agent-rest-wshook": "ws://controller.api.example.com", // Optional REST controller websocket URL from which you can listen to notifications
    "agent-rest-token": "sample_auth_token" // Optional authorization header to be based to rest endpoint for each request
})
```

### Vue.js

See [`vue-framework-go`](https://github.com/hyperledger/aries-framework-go/tree/master/cmd/aries-js-worker/vue-aries-framework-go) for a sample agent built with Vue.js.

Note: is the webpack devserver (`npm run serve`) not working for you? Note the points about
[serving the assets](#important---serving-the-assets) below. See how `vue-aries-framework-go`
[fixes this](https://github.com/hyperledger/aries-framework-go/blob/master/cmd/aries-js-worker/vue-aries-framework-go/scripts/serve.sh).

### Node.js

> **Note:** currently broken, see [#1237](https://github.com/hyperledger/aries-framework-go/issues/1237)

```js
const { Framework } = require('./node_modules/@hyperledger/aries-framework-go/dist/node/aries.js');

const aries = await new Framework({
    assetsPath: process.cwd() + "/node_modules/@hyperledger/aries-framework-go/dist/assets",
    "agent-default-label": "dem-js-agent",
    "http-resolver-url": [],
    "auto-accept": true,
    "outbound-transport": ["ws", "http"],
    "transport-return-route": "all",
    "log-level": "debug",
    "db-namespace":"demoagent"
})
```

### Important - Serving the Assets

Note: this applies if you are running in the browser.

`aries-js-worker` loads some assets at runtime: the web assembly binary and a couple of JS scripts. These assets are
located in the `dist/assets` directory (if you `npm install` it, you'll find them in
`./node_modules/@hyperledger/aries-framework-go/dist/assets`).

Things that need to work if you are to use `aries-js-worker` on the client side:

#### Headers

Make sure the content server adds the appropriate headers when serving the compressed `aries-js-worker.wasm` file.
`aries-js-worker` uses the [Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API) to fetch the wasm.

Examples:

**Serving gzipped wasm:**

Headers:

* `Content-Type: application/wasm`
* `Content-Encoding: gzip`

**Serving wasm compressed with brotli:**

If your browser supports it, then the headers are:

* `Content-Type: application/wasm`
* `Content-Encoding: br`

Note, however, that your browser may not support this compression mode.
 
Not all browsers include `br` in `Accept-Encoding` when using `fetch()` (Firefox doesn't) and it is impossible to
override because `Accept-Encoding` is a [forbidden header name](https://fetch.spec.whatwg.org/#forbidden-header-name).

**Serving uncompressed wasm (not recommended):**

Headers:

* `Content-Type: application/wasm`

#### Path

The URL used to fetch the WASM file is **always** `<assetsPath>/aries-js-worker.wasm`.
This path needs to exist even if your content server is serving a compressed version.

#### Configuring your content server

Here are some examples:

**Nginx**

[Sending compressed files](https://docs.nginx.com/nginx/admin-guide/web-server/compression/#sending-compressed-files):
enabling `gzip_static` on a location will automatically serve requests to `http://example.com/assets/aries-js-worker.wasm`
with `aries-js-worker.wasm.gz` if it exists.

Example: Nginx serving your assets under `/public/assets` with gzipped wasm:

```
location ~ aries-js-worker\.wasm$ {
    gzip_static on;
    types {
        application/wasm  wasm;
    }
}
```

Files in `/public/assets`:

```
assets
├── aries-js-worker.wasm.gz
├── wasm_exec.js
├── worker-impl-node.js
└── worker-impl-web.js
```

Requests for `http://example.com/public/assets/aries-js-worker.wasm` will be served with the `.gz` file.

**goexec**

Here is a hacky one-liner when using [`goexec`](https://github.com/shurcooL/goexec) (for development purposes):

```
goexec -quiet 'http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {dir := http.Dir("."); if strings.HasSuffix(r.RequestURI, ".wasm") && !strings.Contains(r.RequestURI, "wasm=") {w.Header().Add("Content-Encoding", "gzip"); w.Header().Add("Content-Type", "application/wasm"); fmt.Sprintf(r.URL.Path); file, err := dir.Open(r.URL.Path + ".gz"); if err != nil {w.Header().Add("x-error", err.Error()); w.WriteHeader(http.StatusInternalServerError); return; }; buf := make([]byte, 2048); for err == nil { n := 0; n, err = file.Read(buf);if n > 0 {n, err = w.Write(buf[:n]);}}; if !errors.Is(err, io.EOF) {w.WriteHeader(http.StatusInternalServerError); return;}; }; http.FileServer(http.Dir(".")).ServeHTTP(w, r) }); http.ListenAndServe(":8080", nil)'
```

