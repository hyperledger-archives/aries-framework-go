# Aries JS Worker

Aries Framework Go via Javascript.

## Build it

To build you will need:

* Go 1.13.x
* npm 6.13.x
* Node.JS 12.14.x
* bash

Run `npm install` from this directory. The output bundles will be placed in `dist/`.

## Usage

**Node.js**

View [`App.js`](./App.js) for examples.

**Browser**

View [`index.html`](./index.html) for examples.

**Important:** Make sure the web server adds the appropriate headers when serving the compressed `aries-js-worker.wasm.gz` file:

* `Content-Type: application/wasm`
* `Content-Encoding: gzip`

Consult your web server's documentation for instructions on how to do this (eg. for Apache: [Content-Type](https://httpd.apache.org/docs/2.4/mod/mod_mime.html#addtype), [Content-Encoding](https://httpd.apache.org/docs/2.4/mod/mod_deflate.html#precompressed)).

Here is a hacky one-liner when using [`goexec`](https://github.com/shurcooL/goexec):

```
goexec -quiet 'http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { if strings.HasSuffix(r.RequestURI, ".gz") && !strings.Contains(r.RequestURI, "wasm=") { w.Header().Add("Content-Encoding", "gzip"); w.Header().Add("Content-Type", "application/wasm") }; http.FileServer(http.Dir(`.`)).ServeHTTP(w, r) }); http.ListenAndServe(`:8080`, nil)'
```

