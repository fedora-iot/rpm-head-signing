#!/usr/bin/env python
import base64
import subprocess
from tempfile import mkdtemp
import os.path
import shutil

import six


def insert_signature(rpm_path, sig_path, ima_lookup_path=None, ima_presigned_path=None):
    if ima_presigned_path is None:
        ima_presigned_tempdir = None
        ima_args = []
    else:
        ima_presigned_tempdir = mkdtemp(prefix="rpm_signing-", suffix="ima_presigned")
        ima_args = [
            '--define',
            '_file_signing_key %s' % ima_presigned_tempdir,
            '--signfiles',
        ]
        with open(ima_presigned_path, "rt") as f:
            for line in f.readlines():
                line = line.strip()
                (algo, digest, value) = line.split(' ')
                value = base64.b64decode(value)
                fname = os.path.join(ima_presigned_tempdir, '%s_%s' % (algo, digest))
                with open(fname, 'wb') as f:
                    f.write(value)

    try:
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
    finally:
        if ima_presigned_tempdir:
            shutil.rmtree(ima_presigned_tempdir, ignore_errors=True)


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
