#!/usr/bin/env python
import binascii
import struct

from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
import cryptography.hazmat.primitives.hashes as crypto_hashes
import cryptography.hazmat.primitives.asymmetric.ec as crypto_ec

from .extract_rpm_with_filesigs import _extract_filesigs


def parse_ima_signature(sig):
    if not isinstance(sig, bytearray):
        sig = bytearray(sig)

    if len(sig) < 10:
        return None

    info = {
        "type": sig[0],
        "version": sig[1],
        "alg_id": sig[2],
        "key_id": bytes(sig[3:7]),
        "sig_size": struct.unpack(">H", sig[7:9])[0],
        "error": "Did not finish parsing",
    }

    readable_key_id = binascii.hexlify(sig[3:7])
    if not isinstance(readable_key_id, str):
        readable_key_id = readable_key_id.decode("utf8")
    info["user_readable_key_id"] = readable_key_id

    if info["type"] != 3:
        info["error"] = "Unsupported type"
        return info
    if info["version"] != 2:
        info["error"] = "Unsupported version"
        return info

    if info["alg_id"] == 7:  # SHA224
        info["alg_name"] = "SHA224"
        crypto_algo = crypto_hashes.SHA224()
    elif info["alg_id"] == 4:  # SHA256
        info["alg_name"] = "SHA256"
        crypto_algo = crypto_hashes.SHA256()
    elif info["alg_id"] == 5:  # SHA384
        info["alg_name"] = "SHA384"
        crypto_algo = crypto_hashes.SHA384()
    elif info["alg_id"] == 6:  # SHA512
        info["alg_name"] = "SHA512"
        crypto_algo = crypto_hashes.SHA512()
    else:
        info["error"] = "Unsupported algorithm %d" % info["alg_id"]
        return info
    info["hashing_algorithm"] = crypto_algo
    crypto_algo = Prehashed(crypto_algo)
    info["algorithm"] = crypto_ec.ECDSA(crypto_algo)

    if (len(sig) - 9) != info["sig_size"]:
        info["error"] = "Signature length mismatch: %d (actual) != %d (expected)" % (
            len(sig) - 9,
            info["sig_size"],
        )
        return info

    info["signature"] = bytes(sig[9:])
    info["error"] = None

    return info


def get_rpm_ima_signature_info(rpm_path):
    signatures = _extract_filesigs(rpm_path)
    if signatures is None:
        return None
    siginfos = {}
    for path in signatures:
        siginfos[path] = parse_ima_signature(signatures[path])
    return siginfos
