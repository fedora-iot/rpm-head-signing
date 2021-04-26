#!/usr/bin/env python
from tempfile import TemporaryFile
import subprocess
import os.path

from koji import get_rpm_header, rip_rpm_sighdr, RawHeader
import rpm
import six
import xattr


def _extract_rpm(rpm_path, output_path):
    with TemporaryFile(prefix='rpm-', suffix='.cpio') as cpiof:
        subprocess.check_call(
            [
                'rpm2cpio',
                rpm_path,
            ],
            stdout=cpiof,
        )
        cpiof.seek(0, 0)
        subprocess.check_call(
            [
                'cpio',
                '--extract',
                '--make-directories',
                '--no-preserve-owner',
                '--no-absolute-filenames',
            ],
            stdin=cpiof,
            cwd=output_path,
        )


RPMSIGTAG_FILESIGNATURES = 274


# Koji doesn't support type 8 (string array) for returning
def __get_filesigs_from_rawhdr(raw_hdr):
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
        end = raw_hdr.header.find(six.b('\0'), pos)
        filesig = raw_hdr.header[pos:end]
        filesig = filesig.decode('utf8')
        filesig = bytearray.fromhex(filesig)
        filesigs.append(filesig)
        pos = end + 1
    return filesigs

def _extract_filesigs(rpm_path, output_path):
    sighdr = rip_rpm_sighdr(rpm_path)
    sighdr = RawHeader(sighdr)
    filesigs = __get_filesigs_from_rawhdr(sighdr)

    rpm_hdr = get_rpm_header(rpm_path)
    diridxs = rpm_hdr[rpm.RPMTAG_DIRINDEXES]
    dirnames = rpm_hdr[rpm.RPMTAG_DIRNAMES]
    basenames = rpm_hdr[rpm.RPMTAG_BASENAMES]

    if len(basenames) != len(filesigs):
        raise Exception("Invalid number of file signatures (%d) for basenames (%d)" % (len(filesigs), len(basenames)))
    if len(diridxs) != len(basenames):
        raise Exception("Invalid number of diridxs (%d) for basenames (%d)" % (len(diridxs), len(basenames)))

    for i in range(len(basenames)):
        basename = basenames[i]
        dirname = dirnames[diridxs[i]]
        if dirname.startswith('/'):
            dirname = dirname[1:]
        full_path = os.path.join(output_path, dirname, basename)
        filesig = filesigs[i]
        xattr.setxattr(full_path, 'user.ima', filesig)


def extract_rpm_with_filesigs(rpm_path, output_path):
    _extract_rpm(rpm_path, output_path)
    _extract_filesigs(rpm_path, output_path)


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 3:
        raise Exception('Call: %s <rpm-path> <output-path>' % sys.argv[0])

    extract_rpm_with_filesigs(sys.argv[1], sys.argv[2])
