"""
This package is a Python wrapper for [bom-squad/protobom](https://github.com/bom-squad/protobom/).
It can be used to generate Protobom SBOMs, and convert them to SPDX and CycloneDX.
"""
from functools import cache
from importlib.resources import files
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal

from wasmtime import Engine
from wasmtime import ExitTrap
from wasmtime import Func
from wasmtime import Linker
from wasmtime import Module
from wasmtime import Store
from wasmtime import WasiConfig

from . import sbom_pb2
from .sbom_pb2 import Document

here = Path(__file__).parent.absolute()


@cache
def _writer_wasm() -> bytes:
    with files(__name__).joinpath("writer.wasm").open("rb") as fh:
        return fh.read()


def convert(sbom: Document | bytes, to: Literal["cyclonedx", "spdx"]) -> str:
    """
    Convert a Protobom model to either SPDX or CycloneDX representation.

    This method may be called with either a raw protocol buffer as bytes,
    or an `.sbom_pb2.Document` instance.
    """
    with TemporaryDirectory() as tmpdir:
        stdin_file = Path(tmpdir) / "stdin"
        stdout_file = Path(tmpdir) / "stdout"

        if isinstance(sbom, Document):
            stdin_file.write_bytes(sbom.SerializeToString())
        else:
            stdin_file.write_bytes(sbom)

        wasi = WasiConfig()
        wasi.argv = ["protobom-writer", to]
        wasi.stdin_file = stdin_file
        wasi.stdout_file = stdout_file
        wasi.inherit_stderr()

        engine = Engine()
        store = Store(engine)
        store.set_wasi(wasi)
        linker = Linker(engine)
        linker.define_wasi()
        module = Module(store.engine, _writer_wasm())
        instance = linker.instantiate(store, module)
        start = instance.exports(store)["_start"]
        assert isinstance(start, Func)

        try:
            start(store)
        except ExitTrap as e:
            if e.code != 0:
                raise RuntimeError(f"Writer exited with {e.code}.")

        return stdout_file.read_text()


__all__ = [
    "convert",
    "sbom_pb2",
]
