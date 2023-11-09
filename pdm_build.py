import os
import subprocess
from pathlib import Path

from pdm.backend.hooks.base import Context


def pdm_build_initialize(context: Context) -> None:
    if context.target in ("editable", "wheel"):
        out_dir = (
            context.ensure_build_dir() if context.target == "wheel" else context.root
        )

        # Build Protobuf Definitions
        subprocess.check_call(
            [
                "protoc",
                "--experimental_allow_proto3_optional",
                "protobom_py/sbom.proto",
                f"--python_out={out_dir}",
                f"--pyi_out={out_dir}",
            ],
            cwd=context.root,
        )

        # Build WASM binary
        subprocess.check_call(
            ["go", "build", "-o", out_dir / "protobom_py/writer.wasm"],
            cwd=context.root / "protobom-writer",
            env={
                "GOOS": "wasip1",
                "GOARCH": "wasm",
                **os.environ,
            },
        )


def pdm_build_update_files(context: Context, files: dict[str, Path]) -> None:
    if context.target == "sdist":
        files.pop("protobom_py/sbom_pb2.py", None)
        files.pop("protobom_py/sbom_pb2.pyi", None)
        files.pop("protobom_py/writer.wasm", None)
