# protobom-py

![CI Status](https://github.com/appcensus-app-analysis/protobom-py/actions/workflows/main.yml/badge.svg?branch=main)
![Supported Python Versions](https://shields.io/badge/python-%3E=3.10-blue)
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

### Development Setup

You can install `protobom-py` locally using `pip install -e .` or `pdm install`
if you want to pick up dependencies from the lockfile.
Building from source requires a working [`protoc` compiler](https://protobuf.dev/) >= v25.0 and [Go](https://go.dev/) >= 1.21.
See [`pdm_build.py`](./pdm_build.py) for details.

After making changes to `protobom-writer` or `sbom.proto`, run `pip install -e .` again to rebuild compiled artifacts.

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

### Shipping a release

1. Ensure that CI is passing.
2. Updat `pyproject.toml` with the correct version.
3. Push a matching tag.
4. Manually confirm the deploy step in CI.
