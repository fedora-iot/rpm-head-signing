#!/usr/bin/env python
import rpm
from koji import (RawHeader, get_rpm_header, rpm_hdr_size, find_rpm_sighdr, RPM_TAG_FILEDIGESTALGO, RPM_FILEDIGESTALGO_IDS)


RPMTAG_PAYLOADDIGEST = 5092


class NonHeaderSignablePackage(ValueError):
    pass


def _get_filedigests(rpm_hdr):
    file_digestalgo = rpm_hdr[RPM_TAG_FILEDIGESTALGO]
    file_digestalgo = RPM_FILEDIGESTALGO_IDS[file_digestalgo].lower()
    return file_digestalgo, [x.upper() for x in rpm_hdr[rpm.RPMTAG_FILEDIGESTS]]


def check_header_signable(data):
    rawhdr = RawHeader(data)
    if not rawhdr.index.get(RPMTAG_PAYLOADDIGEST):
        raise NonHeaderSignablePackage("This package cannot be headersigned")


def extract_header(input_path, header_out_path, digest_out_path):
    (sig_start, sig_size) = find_rpm_sighdr(input_path)
    hdr_start = sig_start + sig_size
    hdr_size = rpm_hdr_size(input_path, hdr_start)

    if digest_out_path:
        rpm_hdr = get_rpm_header(input_path)
        file_digestalgo, file_digests = _get_filedigests(rpm_hdr)
        file_digests = set(file_digests)

    with open(input_path, "rb") as f:
        f.seek(hdr_start)
        hdrcts = f.read(hdr_size)
        check_header_signable(hdrcts)

        with open(header_out_path, "wb") as of:
            of.write(hdrcts)

    if digest_out_path:
        with open(digest_out_path, "at") as df:
            for digest in file_digests:
                digest = digest.strip()
                if not digest:
                    continue
                df.write("%s %s\n" % (file_digestalgo, digest))


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 4:
        raise Exception("Call: %s <input-rpm> <output-hdr> <output-digests>" % sys.argv[0])

    extract_header(sys.argv[1], sys.argv[2], sys.argv[3])
