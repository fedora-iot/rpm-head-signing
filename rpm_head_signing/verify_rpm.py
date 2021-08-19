#!/usr/bin/env python
import argparse
from tempfile import mkdtemp
import logging
import os
from shutil import rmtree
import subprocess

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import Hash, SHA1
import cryptography.hazmat.primitives.serialization as crypto_serialization
from cryptography.x509 import load_der_x509_certificate
import xattr

import rpm_head_signing


def get_args():
    parser = argparse.ArgumentParser(description="Tool to check IMA signatures")

    parser.add_argument("rpm_paths", nargs="+")
    parser.add_argument("--debug", action="store_true", default=False)
    parser.add_argument("--cert-path")
    parser.add_argument("--lite-verify", action="store_true")
    parser.add_argument("--skip-evmctl", action="store_true", default=False)
    parser.add_argument("--skip-manual-sigcheck", action="store_true", default=False)
    parser.add_argument("--skip-keyid-check", action="store_true", default=False)
    parser.add_argument("--tmp-path-dir", default=".")
    parser.add_argument("--keep-tmp-dir", action="store_true", default=False)

    return parser


def main(args):
    if args.cert_path:
        with open(args.cert_path, "rb") as f:
            cert = load_der_x509_certificate(f.read(), backend=default_backend())
            pubkey = cert.public_key()

            if not args.skip_keyid_check:
                keybytes = pubkey.public_bytes(
                    crypto_serialization.Encoding.X962,
                    crypto_serialization.PublicFormat.UncompressedPoint,
                )
                keybytes_digester = Hash(
                    SHA1(),  # nosec
                    backend=default_backend(),
                )
                keybytes_digester.update(keybytes)
                keybytes_digest = keybytes_digester.finalize()
                correct_keyid = keybytes_digest[-4:]
                logging.info("Correct key ID: %s", correct_keyid)
            else:
                correct_keyid = None
                logging.warning("Skipping correct key ID check")
    elif not args.lite_verify:
        logging.critical("Not using lite verification, so cert-path is required")
        return False

    workdir = mkdtemp(prefix="verify_rpm-", dir=args.tmp_path_dir)
    logging.info("Working directory: %s", workdir)

    had_error = False

    for rpm_path in args.rpm_paths:
        if not os.path.exists(rpm_path):
            logging.warning("Path %s not found", rpm_path)
            had_error = True
            continue
        logging.info("Processing RPM %s", rpm_path)
        extracted_dir = os.path.join(
            workdir,
            rpm_path.rstrip(".rpm").replace("/", "_"),
        )
        os.mkdir(extracted_dir)

        try:
            sigs = rpm_head_signing.get_rpm_ima_signature_info(rpm_path)
            logging.debug("Parsed signatures: %s", sigs)
            logging.info("Verifying signature data...")
            for path in sigs:
                sig = sigs[path]
                if sig["error"]:
                    raise Exception("Error parsing signature: %s" % sig["error"])

                if sig["type"] != 3:
                    raise Exception(
                        "Unexpected type encounterd: %d != 3 (expected)" % sig["type"]
                    )

                if sig["version"] != 2:
                    raise Exception(
                        "Unexpected version encountered: %s != 2 (expected)"
                        % sig["version"]
                    )

                if correct_keyid:
                    if sig["key_id"] != correct_keyid:
                        raise Exception(
                            "Unexpected key ID encountered: %s != %s (expected)"
                            % (sig["key_id"], correct_keyid)
                        )

                # TODO: Check it against the actual digest?

            logging.info("Verified signature data")

            if args.lite_verify:
                logging.info("Skipping live signature verification")
                continue

            logging.debug("Extracting RPM into %s...", extracted_dir)
            rpm_head_signing.extract_rpm_with_filesigs(
                rpm_path,
                extracted_dir,
            )
            logging.debug("Extracted RPM, verifying signatures...")

            for (where, _, fnames) in os.walk(extracted_dir):
                for fname in fnames:
                    file_path = os.path.join(where, fname)
                    logging.debug("Verifying file %s ...", file_path)

                    if not args.skip_evmctl:
                        logging.debug("Calling evmctl")
                        # EVMCTL check
                        subprocess.check_call(
                            [
                                "evmctl",
                                "-v",
                                "--key",
                                args.cert_path,
                                "ima_verify",
                                "--xattr-user",
                                file_path,
                            ]
                        )

                    if not args.skip_manual_sigcheck:
                        # Manual sig check
                        logging.debug("Manual signature check")
                        file_error = manual_sigcheck(file_path, correct_keyid, pubkey)
                        if file_error:
                            logging.warning("File %s failed verification", file_path)
                            had_error = True

                    logging.debug("File verified")

        except Exception:
            logging.warning("Error during verification", exc_info=True)
            had_error = True

    if not args.keep_tmp_dir:
        rmtree(workdir)

    return not had_error


def manual_sigcheck(file_path, correct_keyid, pubkey):
    ima_sig = xattr.getxattr(file_path, "user.ima")
    if not ima_sig:
        logging.warning("No IMA signature found")
        return False
    ima_sig = bytearray(ima_sig)

    ima_sig_info = rpm_head_signing.parse_ima_signature(ima_sig)
    if ima_sig_info["error"]:
        logging.warning("Error parsing signature: %s", ima_sig_info["error"])
        return False
    if ima_sig_info["type"] != 3:
        logging.warning("Invalid signature type")
        return False
    if ima_sig_info["version"] != 2:
        logging.warning("Invalid signature version")
        return False
    if correct_keyid:
        if ima_sig_info["key_id"] != correct_keyid:
            logging.warning("Key ID invalid")
            return False
    hasher = Hash(
        ima_sig_info["hashing_algorithm"],
        backend=default_backend(),
    )
    with open(file_path, "rb") as f:
        hasher.update(f.read())
    file_digest = hasher.finalize()
    pubkey.verify(
        ima_sig_info["signature"],
        bytes(file_digest),
        ima_sig_info["algorithm"],
    )


def __main__():
    args = get_args().parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    if not main(args):
        raise Exception("At least one exception was thrown during validation")


if __name__ == "__main__":
    __main__()
