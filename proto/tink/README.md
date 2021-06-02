# How to generate ecdh_aead and bbs protobufs

To execute the proto generation of `protos/tink/ecdh_aead.proto`, `protos/tink/bbs.proto`, `protos/aes_cbc.proto` and `protos/aes_cbc_hmac_aead.proto`
copy these files into `tink/proto` folder then cd to Tink's Go proto folder `/tink/go/proto`. Copying the protos to Tink is required because of
the dependencies needed to generate the Go protobuf. 

The following steps will generate the protobuf files in Tink:
1. Edit Tink's proto file `proto/BUILD.bazel` to add proto library definitions by adding the following to the file:
```
# -----------------------------------------------
# ecdh_aead
# -----------------------------------------------
proto_library(
    visibility = ["//visibility:public"],
    name = "ecdh_aead_proto",
    srcs = [
        "ecdh_aead.proto",
    ],
    deps = [
        ":common_proto",
        ":tink_proto",
    ],
)
# -----------------------------------------------
# bbs
# -----------------------------------------------
proto_library(
    visibility = ["//visibility:public"],
    name = "bbs_proto",
    srcs = [
        "bbs.proto",
    ],
    deps = [
        ":common_proto",
    ],
)
# -----------------------------------------------
# aes_cbc
# -----------------------------------------------
proto_library(
    visibility = ["//visibility:public"],
    name = "aes_cbc_proto",
    srcs = [
        "aes_cbc.proto",
    ],
)
# -----------------------------------------------
# aes_cbc_hmac_aead
# -----------------------------------------------
proto_library(
    visibility = ["//visibility:public"],
    name = "aes_cbc_hmac_aead_proto",
    srcs = [
        "aes_cbc_hmac_aead.proto",
    ],
    deps = [
        ":aes_cbc_proto",
        ":hmac_proto",
    ],
)
```
Note: if you don't have Bazlisk installed, Tink's build tool, please do so before proceeding. 
Hint, use an alias to call `bazel` commands: `alias bazel='bazelisk'`

2. Add the bazel Go proto build targets by adding the following to `go/proto/BUILD.bazel`:

```
go_proto_library(
    name = "ecdh_aead_go_proto",
    importpath = "github.com/google/tink/go/proto/ecdh_aead_go_proto",
    proto = "@tink_base//proto:ecdh_aead_proto",
    deps = [
        ":common_go_proto",
        ":tink_go_proto",
    ],
)
go_proto_library(
    name = "bbs_go_proto",
    importpath = "github.com/google/tink/go/proto/bbs_go_proto",
    proto = "@tink_base//proto:bbs_proto",
    deps = [
        ":common_go_proto",
    ],
)
go_proto_library(
    name = "aes_cbc_go_proto",
    importpath = "github.com/google/tink/go/proto/aes_cbc_go_proto",
    proto = "@tink_base//proto:aes_cbc_proto",
)
go_proto_library(
    name = "aes_cbc_hmac_aead_go_proto",
    importpath = "github.com/google/tink/go/proto/aes_cbc_hmac_aead_go_proto",
    proto = "@tink_base//proto:aes_cbc_hmac_aead_proto",
    deps = [
        ":aes_cbc_go_proto",
        ":hmac_go_proto",
    ],
)
```

3. To build the Go protobuf, CD into `tink/go/proto`, then make sure to first clean bazel from all builds by running:
```shell script
bazel clean
```

4. Run the bazel builds for the added targets above as follows:
```shell script
bazel build ecdh_aead_go_proto bbs_go_proto aes_cbc_go_proto aes_cbc_hmac_aead_go_proto
```
This will generate new Go protobuf files in Bazel's output path, for example on a Mac it would be under:
* `tink/go/bazel-bin/proto/darwin_amd64_stripped/ecdh_aead_go_proto%/github.com/google/tink/go/proto/ecdh_aead_go_proto/ecdh_aead.pb.go`
* `tink/go/bazel-bin/proto/darwin_amd64_stripped/bbs_go_proto%/github.com/google/tink/go/proto/bbs_go_proto/bbs.pb.go`
* `tink/go/bazel-bin/proto/darwin_amd64_stripped/bbs_go_proto%/github.com/google/tink/go/proto/aes_cbc_go_proto/aes_cbc.pb.go`
* `tink/go/bazel-bin/proto/darwin_amd64_stripped/bbs_go_proto%/github.com/google/tink/go/proto/aes_cbc_hmac_aead_go_proto/aes_cbc_hmac_aead.pb.go`

5. Copy these generated files in Aries's proto paths below in their respective location:
* `aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto/ecdh_aead.pb.go`
* `aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/bbs_go_proto/bbs.pb.go`
* `aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/aes_cbc_go_proto/aes_cbc.pb.go`
* `aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/aes_cbc_hmac_aead_go_proto/aes_cbc_hmac_aead.pb.go`

6. update aes_cbc_proto import in `aes_cbc_hmac_aead.pb.go` since it's part of AFGO as copied above:
   
    from   
    * `aes_cbc_go_proto "github.com/google/tink/go/proto/aes_cbc_go_proto"`
    
    to
    * `aes_cbc_go_proto "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/aes_cbc_go_proto"`

You're done!

Note: the main advantage of running Tink's build tool to generate the protobuf over calling protoc like:
`protoc -I=. --go_out=./tmp-proto protos/ecdhes_aead.proto protos/bbs.proto protos/aes_cbc.proto protos/aes_cbc_hmac_aead.proto` is the fact that the generated Go protobuf imports will be updated correctly.
Bazel's build do use their target importPath instead of relying on the proto's `go_package` option. This results in differing import paths when
generating the protobuf between the tools.
