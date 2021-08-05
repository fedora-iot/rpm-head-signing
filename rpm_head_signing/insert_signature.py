#!/usr/bin/env python
import base64
import binascii
import struct

from .insertlib import insert_signatures as insertlib_insert_signatures


def _fix_sig_size_byteorder(signature):
    sig_size_orig = struct.unpack(">H", signature[6:8])[0]
    sig_size_reversed = struct.unpack("<H", signature[6:8])[0]
    if sig_size_orig == (len(signature) - 8):
        # The byte order was already correct, don't change it
        return signature
    elif sig_size_reversed == (len(signature) - 8):
        print("Reversed byte-order sig_size encountered, fixing")
        sig_size_fixed = struct.pack(">H", sig_size_reversed)
        return signature[:6] + sig_size_fixed + signature[8:]
    else:
        raise Exception(
            "Signature with invalid sig_size encountered: %d != %d"
            % (sig_size_orig, len(signature) - 8)
        )


def insert_signature(rpm_path, sig_path, ima_presigned_path=None, return_header=False):
    """
    Insert a signature back into an RPM.

    Either writes the signature back to the RPM (return_header=False) or returns
    the signature header blob (return_header=True)
    """
    if return_header:
        return_header = 1
    else:
        return_header = 0

    if sig_path:
        # Add RSA Header record
        with open(sig_path, "rb") as sigfile:
            rpm_signature = bytearray(sigfile.read())
    else:
        rpm_signature = None

    # Add IMA signature record
    if ima_presigned_path is None:
        return insertlib_insert_signatures(
            return_header,
            rpm_path,
            rpm_signature,
        )
    else:
        ima_signature_lookup = {}
        with open(ima_presigned_path, "r") as sigpath:
            for line in sigpath.readlines():
                algo, digest, signature = line.strip().split(" ")
                signature = base64.b64decode(signature)
                signature = _fix_sig_size_byteorder(signature)
                signature = binascii.hexlify(b"\x03" + signature)
                if algo not in ima_signature_lookup:
                    ima_signature_lookup[algo] = {}
                ima_signature_lookup[algo][digest.lower()] = signature

        return insertlib_insert_signatures(
            return_header,
            rpm_path,
            rpm_signature,
            ima_signature_lookup,
        )


def _main():
    import sys

    if len(sys.argv) == 3:
        ima_presigned_path = None
    elif len(sys.argv) == 5:
        ima_presigned_path = sys.argv[4]
    else:
        raise Exception("Call: %s <rpm-path> <header-signature> [ima_presigned_path]")

    insert_signature(sys.argv[1], sys.argv[2], ima_presigned_path)


if __name__ == "__main__":
    _main()
