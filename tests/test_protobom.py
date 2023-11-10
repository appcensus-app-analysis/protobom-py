import json
from pathlib import Path

import pytest

from protobom_py import _writer_wasm
from protobom_py import convert
from protobom_py import sbom_pb2

here = Path(__file__).parent.absolute()


def test_convert():
    """Test conversion from an on-disk Protobom model to SPDX and CycloneDX"""
    spdx = json.loads(
        convert((here / "testdata/curl.spdx.json.proto").read_bytes(), "spdx")
    )
    assert spdx["SPDXID"] == "SPDXRef-DOCUMENT"

    cyclonedx = json.loads(
        convert((here / "testdata/curl.spdx.json.proto").read_bytes(), "cyclonedx")
    )
    assert cyclonedx["bomFormat"] == "CycloneDX"


def test_manual():
    """Test manual creation of a Protobom model and subsequent conversion."""
    # Create a new protobom document
    document = sbom_pb2.Document()

    # Populate some of the document metadata:

    # ...for example the author:
    author = document.metadata.authors.add()
    author.name = "John Doe"

    # ...and the tool that produced the SBOM:
    tool = document.metadata.tools.add()
    tool.name = "ACME SBOM Tool"
    tool.version = "1.0"
    tool.vendor = "ACME Corporation"

    # Create a node to represent the application:
    app_node = document.node_list.nodes.add()
    app_node.id = "pkg:generic/my-software@v1.0.0"
    app_node.primary_purpose.append(sbom_pb2.Purpose.APPLICATION)
    app_node.name = "My Software Name"
    app_node.version = "v1.0.0"
    app_node.licenses.extend(["Apache-2.0"])
    app_node.license_concluded = "Apache-2.0"
    app_node.license_comments = "Apache License"

    # Create two nodes to describe files in the application
    node1 = document.node_list.nodes.add()
    node1.id = "File--usr-lib-libsoftware.so"
    node1.type = sbom_pb2.Node.FILE
    node1.name = "/usr/lib/libsoftware.so"
    node1.version = "1"
    node1.copyright = "Copyright 2023 The ACME Corporation"
    node1.description = "Software Lib"

    node1.hashes[
        sbom_pb2.HashAlgorithm.SHA1
    ] = "f3ae11065cafc14e27a1410ae8be28e600bb8336"
    node1.hashes[
        sbom_pb2.HashAlgorithm.SHA256
    ] = "4f232eeb99e1663d07f0af1af6ea262bf594934b694228e71fd8f159f9a19f32"
    node1.hashes[
        sbom_pb2.HashAlgorithm.SHA512
    ] = "8044d0df34242699ad73bfe99b9ac3d6bbdaa4f8ebce1e23ee5c7f9fe59db8ad7b01fe94e886941793aee802008a35b05a30bc51426db796aa21e5e91b7ed9be"

    node2 = document.node_list.nodes.add()
    node2.id = "File--usr-bin-software"
    node2.type = sbom_pb2.Node.FILE
    node2.name = "/usr/bin/software"
    node2.version = "1.0"
    node2.copyright = "Copyright 2023 The ACME Corporation"
    node2.description = "Software binary"

    node2.hashes[
        sbom_pb2.HashAlgorithm.SHA1
    ] = "defee82004d22fc92ab81c0c952a62a2172bda8c"
    node2.hashes[
        sbom_pb2.HashAlgorithm.SHA256
    ] = "ad291c9572af8fc2ec8fd78d295adf7132c60ad3d10488fb63d120fc967a4132"
    node2.hashes[
        sbom_pb2.HashAlgorithm.SHA512
    ] = "5940d8647907831e77ec00d81b318ca06655dbb0fd36d112684b03947412f0f98ea85b32548bc0877f3d7ce8f4de9b2c964062df44742b98c8e9bd851faecce9"

    spdx = json.loads(convert(document, "spdx"))

    # Protobuf randomizes map order, so we sort to ensure equality.
    spdx["files"] = sorted(spdx["files"], key=lambda x: x["SPDXID"])
    for file in spdx["files"]:
        file["checksums"] = sorted(file["checksums"], key=lambda x: x["algorithm"])

    assert spdx == {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": spdx["creationInfo"]["created"],
            "creators": ["Tool: protobom-devel", "Tool: ACME SBOM Tool-1.0"],
            "licenseListVersion": "3.20",
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://spdx.org/spdxdocs/",
        "files": [
            {
                "SPDXID": "SPDXRef-File--usr-bin-software",
                "checksums": [
                    {
                        "algorithm": "SHA1",
                        "checksumValue": "defee82004d22fc92ab81c0c952a62a2172bda8c",
                    },
                    {
                        "algorithm": "SHA256",
                        "checksumValue": "ad291c9572af8fc2ec8fd78d295adf7132c60ad3d10488fb63d120fc967a4132",
                    },
                    {
                        "algorithm": "SHA512",
                        "checksumValue": "5940d8647907831e77ec00d81b318ca06655dbb0fd36d112684b03947412f0f98ea85b32548bc0877f3d7ce8f4de9b2c964062df44742b98c8e9bd851faecce9",
                    },
                ],
                "copyrightText": "Copyright 2023 The ACME Corporation",
                "fileName": "/usr/bin/software",
            },
            {
                "SPDXID": "SPDXRef-File--usr-lib-libsoftware.so",
                "checksums": [
                    {
                        "algorithm": "SHA1",
                        "checksumValue": "f3ae11065cafc14e27a1410ae8be28e600bb8336",
                    },
                    {
                        "algorithm": "SHA256",
                        "checksumValue": "4f232eeb99e1663d07f0af1af6ea262bf594934b694228e71fd8f159f9a19f32",
                    },
                    {
                        "algorithm": "SHA512",
                        "checksumValue": "8044d0df34242699ad73bfe99b9ac3d6bbdaa4f8ebce1e23ee5c7f9fe59db8ad7b01fe94e886941793aee802008a35b05a30bc51426db796aa21e5e91b7ed9be",
                    },
                ],
                "copyrightText": "Copyright 2023 The ACME Corporation",
                "fileName": "/usr/lib/libsoftware.so",
            },
        ],
        "name": "",
        "packages": [
            {
                "SPDXID": "SPDXRef-pkg:generic/my-software@v1.0.0",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseComments": "Apache License",
                "licenseConcluded": "Apache-2.0",
                "name": "My Software Name",
                "primaryPackagePurpose": "APPLICATION",
                "versionInfo": "v1.0.0",
            }
        ],
        "spdxVersion": "SPDX-2.3",
    }


def test_invalid_protobom():
    with pytest.raises(RuntimeError):
        convert(b"invalid", "spdx")


def test_invalid_format():
    with pytest.raises(RuntimeError):
        convert((here / "testdata/curl.spdx.json.proto").read_bytes(), "invalid")  # type: ignore


def test_has_wasm():
    """This test merely asserts that the WASM blob is available."""
    assert _writer_wasm()
