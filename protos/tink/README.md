# How to generate ecdhes_aead protobuf

To execute the proto generation of `ecdhes_aead.proto`, copy this file into
`tink/proto` folder then cd to Tink's Go proto folder `/tink/go/proto`. Copying the proto to Tink is required because of
the dependencies needed to generate the Go protobuf. 

The following steps will generate the protobuf in Tink:
1. Edit Tink's proto file `proto/BUILD.bazel` to add a proto library definition by adding the following to the file:
```

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
        ":common_proto",
        ":tink_proto",
    ],
)

```
Note: if you don't have Bazlisk installed, Tink's build tool, please do so before proceeding. 
Hint, use an alias to call `bazel` commands: `alias bazel='bazelisk'`

2. Add the bazel Go proto build target by adding the following to `go/proto/BUILD.bazel`:
```

go_proto_library(
    name = "ecdhes_aead_go_proto",
    importpath = "github.com/google/tink/go/proto/ecdhes_aead_go_proto",
    proto = "@tink_base//proto:ecdhes_aead_proto",
    deps = [
        ":common_go_proto",
        ":tink_go_proto",
    ],
)

```

3. To build the Go protobuf, CD into `tink/go/proto`, then make sure to first clean bazel from all builds by running:
```shell script
bazel clean
```

4. Run the bazel build for the added target above as follows:
```shell script
bazel build ecdhes_aead_go_proto
```
This will generate a new Go protobuf file in Bazel's output path, for example on a Mac it would be under:
`tink/go/bazel-bin/proto/darwin_amd64_stripped/ecdhes_aead_go_proto%/github.com/google/tink/go/proto/ecdhes_aead_go_proto/ecdhes_aead.pb.go`

5. Copy this generated file in Aries's proto path below:
`aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdhes_aead_go_proto/ecdhes_aead.pb.go`

You're done!

Note: the main advantage of running Tink's build tool to generate the protobuf over calling protoc like:
`protoc -I=. --go_out=./tmp-proto proto/ecdhes_aead.proto` is the fact that the generated Go protobuf imports will be updated correctly.
Bazel's build do use their target importPath instead of relying on the proto's `go_package` option. This results in differing import paths when
generating the protobuf between the tools.
