#!/usr/bin/env python
from tempfile import TemporaryFile
import subprocess
import os.path
import sys

from koji import get_rpm_header, rip_rpm_sighdr, RawHeader
import rpm
import xattr


rpm_version = subprocess.check_output(["rpm", "--version"])
# Example: RPM version 4.16.90
rpm_version = rpm_version.split(b" ")[2].split(b".")
# Ignore the last bit, which could be e.g. 0-beta1
rpm_version = tuple(map(int, rpm_version[:2]))
if rpm_version[0] != 4:
    raise Exception("RPM version %s is not major version 4" % rpm_version)


def _extract_rpm(rpm_path, output_path):
    # To deal with zstd on RPM 4.11
    if rpm_version[1] == 11:
        rpm2cpio = "./test_assets/rpm2cpio.sh"
    else:
        rpm2cpio = "rpm2cpio"

    with TemporaryFile(prefix="rpm-", suffix=".cpio") as cpiof:
        subprocess.check_call(
            [
                rpm2cpio,
                rpm_path,
            ],
            stdout=cpiof,
        )
        cpiof.seek(0, 0)
        subprocess.check_call(
            [
                "cpio",
                "--extract",
                "--make-directories",
                "--no-preserve-owner",
                "--no-absolute-filenames",
            ],
            stdin=cpiof,
            cwd=output_path,
        )


RPMSIGTAG_FILESIGNATURES = 274
RPMSIGTAG_FILESIGNATURELENGTH = 275
RPMSIGTAG_RESERVEDSPACE = 1008
RPMSIGTAG_PGP = 259
RPMSIGTAG_RSAHEADER = 268


# Koji doesn't support type 8 (string array) for returning
def _get_header_type_8(raw_hdr, tag):
    entry = raw_hdr.index.get(RPMSIGTAG_FILESIGNATURES)
    if entry is None:
        raise Exception("No file signatures found")
    (dtype, offset, count) = entry[1:]
    # This is basically RawHeader._getitem, but then for only type 8
    il = len(raw_hdr.index)
    store = 16 + il * 16
    pos = store + offset
    filesigs = []
    for i in range(count):
        if sys.version_info.major == 2:
            end = raw_hdr.header.find("\0", pos)
        elif sys.version_info.major == 3:
            end = raw_hdr.header.find(b"\0", pos)
        else:
            raise Exception("Unsupported Python")
        filesig = raw_hdr.header[pos:end]
        filesig = filesig.decode("utf8")
        filesig = bytearray.fromhex(filesig)
        filesigs.append(filesig)
        pos = end + 1
    return filesigs


def _extract_filesigs(rpm_path):
    sighdr = rip_rpm_sighdr(rpm_path)
    sighdr = RawHeader(sighdr)
    filesigs = _get_header_type_8(sighdr, RPMSIGTAG_FILESIGNATURES)

    if not filesigs:
        return None

    rpm_hdr = get_rpm_header(rpm_path)
    diridxs = rpm_hdr[rpm.RPMTAG_DIRINDEXES]
    dirnames = rpm_hdr[rpm.RPMTAG_DIRNAMES]
    basenames = rpm_hdr[rpm.RPMTAG_BASENAMES]

    if len(basenames) != len(filesigs):
        raise Exception(
            "Invalid number of file signatures (%d) for basenames (%d)"
            % (len(filesigs), len(basenames))
        )
    if len(diridxs) != len(basenames):
        raise Exception(
            "Invalid number of diridxs (%d) for basenames (%d)"
            % (len(diridxs), len(basenames))
        )

    signatures = {}

    for i in range(len(basenames)):
        basename = basenames[i]
        dirname = dirnames[diridxs[i]]
        filesig = filesigs[i]
        if sys.version_info.major == 2:
            filesig = bytes(filesig)
        path = os.path.join(dirname, basename)
        if not isinstance(path, str):
            path = path.decode("utf8")
        signatures[path] = filesig

    return signatures


def _install_filesigs(signatures, output_path):
    for path in signatures:
        full_path = os.path.join(output_path, path.lstrip("/"))
        xattr.setxattr(full_path, "user.ima", signatures[path])


def extract_rpm_with_filesigs(rpm_path, output_path):
    _extract_rpm(rpm_path, output_path)
    filesigs = _extract_filesigs(rpm_path)
    _install_filesigs(filesigs, output_path)


def _main():
    if len(sys.argv) != 3:
        raise Exception("Call: %s <rpm-path> <output-path>" % sys.argv[0])

    extract_rpm_with_filesigs(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    _main()
