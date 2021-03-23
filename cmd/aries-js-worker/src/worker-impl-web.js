/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// args will contain the arguments passed into the worker as query parameters in the worker script's uri.
// We need the parameters "wasm" and "wasmJS" that point to the absolute path of the wasm binary and
// the Go webssembly JS wrapper script respectively.
const args = {};
location.search
    .slice(1)
    .split("&")
    .forEach((param) => {
        const kv = param.split("=");
        args[kv[0]] = kv[1];
    });

const wasmJS = args["wasmJS"];
const wasm = args["wasm"];

self.importScripts(wasmJS);

if (!WebAssembly.instantiateStreaming) {
    // polyfill
    WebAssembly.instantiateStreaming = async (resp, importObject) => {
        const source = await (await resp).arrayBuffer();
        return await WebAssembly.instantiate(source, importObject);
    };
}

const go = new Go();
// Firefox is not including 'br' in fetch() for some reason.
// Cannot override Accept-Encoding header for the fetch call (would've liked to use brotli).
// Accept-Encoding is one of the forbidden headers of the Fetch API: https://fetch.spec.whatwg.org/#forbidden-header-name
WebAssembly.instantiateStreaming(fetch(wasm), go.importObject).then(
    (result) => {
        go.run(result.instance);
    },
    (err) => {
        throw new Error("failed to fetch wasm blob: " + err.message);
    }
);

handleResult = function (r) {
    postMessage(JSON.parse(r));
};

print_log = function (type, err) {
    postMessage({ type: type, msg: err });
};

onmessage = function (m) {
    // handleMsg is not defined here but is instead defined by the WASM blob during initialization
    handleMsg(JSON.stringify(m.data));
};
