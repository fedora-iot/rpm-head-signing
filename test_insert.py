#/usr/bin/env python
import sys

import rpm_head_signing


def main(rpm_path, sig_path, ima_path):
    rpm_head_signing.insert_signature(
        rpm_path,
        sig_path,
        ima_presigned_path=ima_path,
    )


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], sys.argv[3])
