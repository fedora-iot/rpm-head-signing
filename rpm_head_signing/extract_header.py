#!/usr/bin/env python
import rpm
from koji import (get_rpm_header, rpm_hdr_size, find_rpm_sighdr, RPM_TAG_FILEDIGESTALGO, RPM_FILEDIGESTALGO_IDS)


def extract_header(input_path, header_out_path, digest_out_path):
    (sig_start, sig_size) = find_rpm_sighdr(input_path)
    hdr_start = sig_start + sig_size
    hdr_size = rpm_hdr_size(input_path, hdr_start)

    rpm_hdr = get_rpm_header(input_path)
    file_digestalgo = rpm_hdr[RPM_TAG_FILEDIGESTALGO]
    file_digestalgo = RPM_FILEDIGESTALGO_IDS[file_digestalgo].lower()
    file_digests = set([x.upper() for x in rpm_hdr[rpm.RPMTAG_FILEDIGESTS]])

    with open(digest_out_path, "at") as df:
        for digest in file_digests:
            digest = digest.strip()
            if not digest:
                continue
            df.write("%s %s\n" % (file_digestalgo, digest))

    with open(input_path, "rb") as f:
        f.seek(hdr_start)
        with open(header_out_path, "wb") as of:
            of.write(f.read(hdr_size))


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 4:
        raise Exception("Call: %s <input-rpm> <output-hdr> <output-digests>" % sys.argv[0])

    extract_header(sys.argv[1], sys.argv[2], sys.argv[3])
