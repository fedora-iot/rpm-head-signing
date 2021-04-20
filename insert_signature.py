#!/usr/bin/env python
import subprocess


def insert_signature(rpm_path, sig_path, ima_lookup_path=None, ima_presigned_path=None):
    if ima_presigned_path is None:
        ima_args = []
    else:
        ima_args = [
            '--define',
            '_file_signing_key %s' % ima_presigned_path,
            '--signfiles',
        ]

    subprocess.check_call(
        [
            'rpmsign',
            '--define',
            '_gpg_name fakename',
            '--define',
            '__gpg_sign_cmd /usr/bin/cp cp "%s" "%%{__signature_filename}"' % sig_path,
            '--addsign',
            rpm_path,
        ] + ima_args,
        env={
            'LD_PRELOAD': ima_lookup_path,
        },
    )


if __name__ == '__main__':
    import sys

    if len(sys.argv) == 3:
        ima_lookup_path = None
        ima_presigned_path = None
    elif len(sys.argv) == 5:
        ima_lookup_path = sys.argv[3]
        ima_presigned_path = sys.argv[4]
    else:
        raise Exception("Call: %s <rpm-path> <header-signature> [ima_lookup.so_path] [ima_presigned_directory]")

    insert_signature(sys.argv[1], sys.argv[2], ima_lookup_path, ima_presigned_path)
