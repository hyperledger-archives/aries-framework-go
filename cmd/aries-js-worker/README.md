# Aries JS Worker

Aries Framework Go via Javascript.

## Build it

To build you will need:

* Go 1.14.x
* npm 6.13.x
* Node.JS 12.14.x
* bash

Run `npm install` from this directory. The output bundles will be placed in `dist/`.

## Usage

### Node.js

View [`App.js`](./App.js) for examples.

### Vue.js

Go to [`vue-framework-go`](./vue-aries-framework-go) for a sample agent built with Vue.js.

Note: is the webpack devserver (`npm run serve`) not working for you? Note the points about
[serving the assets](#important---serving-the-assets) below. See how `vue-aries-framework-go`
[fixes this](vue-aries-framework-go/scripts/serve.sh).

### Browser

View [`index.html`](./index.html) for examples.

### Important - Serving the Assets

`aries-js-worker` loads some assets at runtime: the web assembly binary and a couple of JS scripts. These assets are
located in the `dist/assets` directory (if you `npm install` it, you'll find them in
`./node_modules/@hyperledger/aries-framework-go/dist/assets`).

Things that need to work if you are to use `aries-js-worker` on the client side.

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

