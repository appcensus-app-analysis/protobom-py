pushd ./protobom-writer
GOARCH=wasm GOOS=wasip1 go build -o protobom-writer.wasm protobom-writer.go
popd

pushd ./protobom_py
protoc protobom_py/sbom.proto --python_out=. --experimental_allow_proto3_optional
popd

