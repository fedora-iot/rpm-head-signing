#!/usr/bin/env python
import base64
import binascii
import subprocess
from tempfile import mkdtemp
import os.path
import shutil
import struct

import koji

from .insertlib import insert_signatures as insertlib_insert_signatures


def insert_signature(rpm_path, sig_path, ima_presigned_path=None, return_header=False):
    """
    Insert a signature back into an RPM.

    Either writes the signature back to the RPM (return_header=False) or returns
    the signature header blob (return_header=True)
    """
    # Add RSA Header record
    with open(sig_path, 'rb') as sigfile:
        rpm_signature = sigfile.read()

    # Add IMA signature record
    ima_args = []
    if ima_presigned_path is not None:
        ima_signature_lookup = {}
        with open(ima_presigned_path, 'r', encoding='utf8') as sigpath:
            for line in sigpath.readlines():
                algo, digest, signature = line.strip().split(' ')
                signature = binascii.hexlify(b'\x03' + base64.b64decode(signature))
                if algo not in ima_signature_lookup:
                    ima_signature_lookup[algo] = {}
                # Perhaps: prefix "signature" with "\x03"
                ima_signature_lookup[algo][digest.lower()] = signature
        ima_args = [ima_signature_lookup]

    return insertlib_insert_signatures(
        return_header,
        rpm_path,
        rpm_signature,
        *ima_args,
    )


if __name__ == '__main__':
    import sys

    if len(sys.argv) == 3:
        ima_presigned_path = None
    elif len(sys.argv) == 5:
        ima_presigned_path = sys.argv[4]
    else:
        raise Exception("Call: %s <rpm-path> <header-signature> [ima_presigned_path]")

    insert_signature(sys.argv[1], sys.argv[2], ima_presigned_path)
