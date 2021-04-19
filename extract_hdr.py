#!/usr/bin/env python
import rpm
from koji import (get_rpm_header, rpm_hdr_size, find_rpm_sighdr, RPM_TAG_FILEDIGESTALGO, RPM_FILEDIGESTALGO_IDS)
import sys

if len(sys.argv) != 4:
    raise Exception("Call: %s <input-rpm> <output-hdr> <output-digests>" % sys.argv[0])

path = sys.argv[1]
hdr_out = sys.argv[2]
digests_out = sys.argv[3]

(sig_start, sig_size) = find_rpm_sighdr(path)
hdr_start = sig_start + sig_size
hdr_size = rpm_hdr_size(path, hdr_start)

rpm_hdr = get_rpm_header(path)
file_digestalgo = rpm_hdr[RPM_TAG_FILEDIGESTALGO]
file_digestalgo = RPM_FILEDIGESTALGO_IDS[file_digestalgo].lower()
file_digests = set([x.upper() for x in rpm_hdr[rpm.RPMTAG_FILEDIGESTS]])

with open(digests_out, "wt") as df:
    for digest in file_digests:
        df.write("%s:%s\n" % (file_digestalgo, digest))

with open(path, "rb") as f:
    f.seek(hdr_start)
    with open(hdr_out, "wb") as of:
        of.write(f.read(hdr_size))
