# /usr/bin/env python
import shutil
import sys

import koji

import rpm_head_signing


if __name__ == "__main__":
    mode = sys.argv[1]
    rpm_path = sys.argv[2]
    sig_path = sys.argv[3]
    ima_path = sys.argv[4]

    if sig_path == "none":
        sig_path = None

    if mode == "normal":
        rpm_head_signing.insert_signature(
            rpm_path,
            sig_path,
            ima_presigned_path=ima_path,
        )
    elif mode == "splice_header":
        header = rpm_head_signing.insert_signature(
            rpm_path,
            sig_path,
            ima_presigned_path=ima_path,
            return_header=True,
        )
        header = bytes(header)
        new_path = koji.splice_rpm_sighdr(
            bytes(header),
            rpm_path,
        )
        shutil.move(new_path, rpm_path)
    else:
        raise Exception("Unsupported mode %s" % mode)
