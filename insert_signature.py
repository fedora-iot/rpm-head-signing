#!/usr/bin/env python
import subprocess
import sys

if len(sys.argv) not in (4, 5):
    raise Exception("Call: %s <ima_lookup.so-path> <rpm-path> <header-signature> [ima_presigned_directory]")

ima_lookup_path = sys.argv[1]
rpm_path = sys.argv[2]
sig_path = sys.argv[3]
if len(sys.argv) == 3:
    ima_args = []
else:
    ima_args = [
        '--define',
        '_file_signing_key %s' % sys.argv[4],
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
