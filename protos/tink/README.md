# How to generate common_composite, ecdhes_aead and ecdh1pu_aead protobufs

To execute the proto generation of `protos/tink/common_composite.proto`,  `protos/tink/ecdhes_aead.proto` and `protos/tink/ecdh1pu_aead.proto`, 
copy these files into `tink/proto` folder then cd to Tink's Go proto folder `/tink/go/proto`. Copying the protos to Tink is required because of
the dependencies needed to generate the Go protobuf. 

The following steps will generate the protobuf files in Tink:
1. Edit Tink's proto file `proto/BUILD.bazel` to add proto library definitions by adding the following to the file:
```

# -----------------------------------------------
# common_composite
# -----------------------------------------------
proto_library(
    visibility = ["//visibility:public"],
    name = "common_composite_proto",
    srcs = [
        "common_composite.proto",
    ],
)

# -----------------------------------------------
# ecdhes_aead
# -----------------------------------------------
proto_library(
    visibility = ["//visibility:public"],
    name = "ecdhes_aead_proto",
    srcs = [
        "ecdhes_aead.proto",
    ],
    deps = [
        ":common_composite_proto",
        ":common_proto",
        ":tink_proto",
    ],
)

# -----------------------------------------------
# ecdh1pu_aead
# -----------------------------------------------
proto_library(
    visibility = ["//visibility:public"],
    name = "ecdh1pu_aead_proto",
    srcs = [
        "ecdh1pu_aead.proto",
    ],
    deps = [
        ":common_composite_proto",
        ":common_proto",
        ":tink_proto",
    ],
)

```
Note: if you don't have Bazlisk installed, Tink's build tool, please do so before proceeding. 
Hint, use an alias to call `bazel` commands: `alias bazel='bazelisk'`

2. Add the bazel Go proto build targets by adding the following to `go/proto/BUILD.bazel`:

```
go_proto_library(
    name = "common_composite_go_proto",
    importpath = "github.com/google/tink/go/proto/common_composite_go_proto",
    proto = "@tink_base//proto:common_composite_proto",
)

go_proto_library(
    name = "ecdhes_aead_go_proto",
    importpath = "github.com/google/tink/go/proto/ecdhes_aead_go_proto",
    proto = "@tink_base//proto:ecdhes_aead_proto",
    deps = [
        ":common_composite_go_proto",
        ":common_go_proto",
        ":tink_go_proto",
    ],
)

go_proto_library(
    name = "ecdh1pu_aead_go_proto",
    importpath = "github.com/google/tink/go/proto/ecdh1pu_aead_go_proto",
    proto = "@tink_base//proto:ecdh1pu_aead_proto",
    deps = [
        ":common_composite_go_proto",
        ":common_go_proto",
        ":tink_go_proto",
    ],
)

```

3. To build the Go protobuf, CD into `tink/go/proto`, then make sure to first clean bazel from all builds by running:
```shell script
bazel clean
```

4. Run the bazel builds for the added targets above as follows:
```shell script
bazel build common_composite_go_proto
bazel build ecdhes_aead_go_proto
bazel build ecdh1pu_aead_go_proto
```
This will generate new Go protobuf files in Bazel's output path, for example on a Mac it would be under:
`tink/go/bazel-bin/proto/darwin_amd64_stripped/common_composite_go_proto%/github.com/google/tink/go/proto/common_composite_go_proto/common_composite.pb.go`
`tink/go/bazel-bin/proto/darwin_amd64_stripped/ecdhes_aead_go_proto%/github.com/google/tink/go/proto/ecdhes_aead_go_proto/ecdhes_aead.pb.go`
`tink/go/bazel-bin/proto/darwin_amd64_stripped/ecdh1pu_aead_go_proto%/github.com/google/tink/go/proto/ecdh1pu_aead_go_proto/ecdh1pu_aead.pb.go`

5. Copy these generated files in Aries's proto paths below in their respective location:
* common composite proto: `aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto/common_composite.pb.go`
* ecdh-es proto: `aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdhes_aead_go_proto/ecdhes_aead.pb.go`
* ecdh-1pu proto: `aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh1pu_aead_go_proto/ecdh1pu_aead.pb.go`

6. Manually update the common composite import in ecdh-es and ecdh-1pu pb.go files above to match the patch of the local common_composite.pb.go dependency.
This is required since common composite proto is created above and not found in the Tink repository. Replace:
`common_composite_go_proto "github.com/google/tink/go/proto/common_composite_go_proto"`
with
`common_composite_go_proto "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto"`

You're done!

Note: the main advantage of running Tink's build tool to generate the protobuf over calling protoc like:
`protoc -I=. --go_out=./tmp-proto proto/ecdhes_aead.proto` is the fact that the generated Go protobuf imports will be updated correctly.
Bazel's build do use their target importPath instead of relying on the proto's `go_package` option. This results in differing import paths when
generating the protobuf between the tools.
