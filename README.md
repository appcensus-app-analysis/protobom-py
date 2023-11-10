# protobom-py

![CI Status](https://github.com/appcensus-app-analysis/protobom-py/actions/workflows/main.yml/badge.svg?branch=main)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/protobom-py)
![PyPI - Version](https://img.shields.io/pypi/v/protobom-py)


protobom-py is a Python wrapper for [bom-squad/protobom](https://github.com/bom-squad/protobom/)
that can be used to generate both SPDX and CycloneDX SBOMs from Python code. There are two main parts:

1. **protobom_py.sbom_pb2** provides precompiled Protobuf definitions for the Protobom format.
2. **protobom_py.convert()** can be used to render SPDX and CycloneDX SBOMS from the Protobom format.

## Usage

```python
import protobom_py

document = protobom_py.sbom_pb2.Document()
spdx = protobom_py.convert(document, "spdx")

proto = b"..."
cyclonedx = protobom_py.convert(proto, "cyclonedx")
```

See `tests/test_protobom.py` for more in-depth examples.

## Development

### Tests

The project maintains a strict 100% test coverage. You can run tests locally as follows:
```shell
pdm run test
```

### Code Style

The project enforces a consistent code style using Ruff:

```shell
pdm run fmt
```

### Architecture

`protobom` is written in Go, which makes it tricky to distribute Python bindings.
While projects such as [gopy](https://github.com/go-python/gopy) make it possible to generate CPython
extensions, this approach would require `{Windows, Linux, macOS} x {Python 3.10, Python 3.11, Python 3.12, ...}` 
individual wheel distributions, which is not very sustainable. 
To simplify distribution, `protobom_py` uses an alternative approach:

1. `./protobom-writer` contains a small Go binary that converts a Protobom file to either SPDX or CycloneDX.
2. This binary is compiled to Go's WebAssembly/WASI target.
3. `protobom_py` uses `wasmtime` to execute the wasm binary when `convert()` is called.

The WASM binary works across platforms, so only a single binary distribution is needed.