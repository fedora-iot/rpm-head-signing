from tempfile import mkdtemp
import hashlib
from shutil import rmtree, copy
import os
import os.path
import subprocess
import struct
import sys
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.hashes import Hash, SHA1
import cryptography.hazmat.primitives.serialization as crypto_serialization
import cryptography.hazmat.primitives.hashes as crypto_hashes
import cryptography.hazmat.primitives.asymmetric.ec as crypto_ec
from cryptography.x509 import load_der_x509_certificate
import xattr

import rpm_head_signing


class TestRpmHeadSigning(unittest.TestCase):
    pkg_numbers = ["1", "2"]

    @classmethod
    def setUpClass(cls):
        cls.asset_dir = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "test_assets",
        )

    def setUp(self):
        self.tmpdir = mkdtemp(prefix="test-rpm_head_signing-", dir=os.path.abspath("."))

    def tearDown(self):
        rmtree(self.tmpdir)
        self.tmpdir = None

    def compare_files(self, asset_name, tmp_name):
        with open(os.path.join(self.asset_dir, asset_name), "rb") as asset_file:
            with open(os.path.join(self.tmpdir, tmp_name), "rb") as tmp_file:
                self.assertEqual(
                    asset_file.read().strip(),
                    tmp_file.read().strip(),
                    "Asset file %s is different from tmp file %s"
                    % (asset_name, tmp_name),
                )

    def test_extract(self):
        rpm_head_signing.extract_header(
            os.path.join(self.asset_dir, "testpkg-1.noarch.rpm"),
            os.path.join(self.tmpdir, "testpkg-1.noarch.rpm.hdr.tmp"),
            os.path.join(self.tmpdir, "digests.out.tmp"),
        )
        rpm_head_signing.extract_header(
            os.path.join(self.asset_dir, "testpkg-2.noarch.rpm"),
            os.path.join(self.tmpdir, "testpkg-2.noarch.rpm.hdr.tmp"),
            os.path.join(self.tmpdir, "digests.out.tmp"),
        )

        self.compare_files("testpkg-1.noarch.rpm.hdr", "testpkg-1.noarch.rpm.hdr.tmp")
        self.compare_files("testpkg-2.noarch.rpm.hdr", "testpkg-2.noarch.rpm.hdr.tmp")
        self.compare_files("digests.out", "digests.out.tmp")

    def test_extract_no_digests(self):
        rpm_head_signing.extract_header(
            os.path.join(self.asset_dir, "testpkg-1.noarch.rpm"),
            os.path.join(self.tmpdir, "testpkg-1.noarch.rpm.hdr.tmp"),
            digest_out_path=None,
        )
        rpm_head_signing.extract_header(
            os.path.join(self.asset_dir, "testpkg-2.noarch.rpm"),
            os.path.join(self.tmpdir, "testpkg-2.noarch.rpm.hdr.tmp"),
            digest_out_path=None,
        )

        self.compare_files("testpkg-1.noarch.rpm.hdr", "testpkg-1.noarch.rpm.hdr.tmp")
        self.compare_files("testpkg-2.noarch.rpm.hdr", "testpkg-2.noarch.rpm.hdr.tmp")

    def test_extract_non_hdrsign_able(self):
        with self.assertRaises(rpm_head_signing.NonHeaderSignablePackage):
            rpm_head_signing.extract_header(
                os.path.join(
                    self.asset_dir, "sblim-cim-client-javadoc-1.3.9.1-1.el6.noarch.rpm"
                ),
                os.path.join(
                    self.tmpdir,
                    "sblim-cim-client-javadoc-1.3.9.1-1.el6.noarch.rpm.hdr.tmp",
                ),
                os.path.join(self.tmpdir, "digests.out.tmp"),
            )
        self.assertFalse(os.path.exists(os.path.join(self.tmpdir, "digests.out.tmp")))

    def test_insert_no_ima(self):
        copy(
            os.path.join(self.asset_dir, "gpgkey.asc"),
            os.path.join(self.tmpdir, "gpgkey.key"),
        )
        for pkg in self.pkg_numbers:
            copy(
                os.path.join(self.asset_dir, "testpkg-%s.noarch.rpm" % pkg),
                os.path.join(self.tmpdir, "testpkg-%s.noarch.rpm" % pkg),
            )
            res = subprocess.check_output(
                [
                    "rpm",
                    "--define",
                    "%%_keyringpath %s" % self.tmpdir,
                    "--define",
                    "%%_keyringpath %s" % self.tmpdir,
                    "-Kv",
                    os.path.join(self.tmpdir, "testpkg-%s.noarch.rpm" % pkg),
                ],
            )
            self.assertTrue(b"SHA1 digest: OK" in res)
            self.assertFalse(b"Header V3 RSA" in res)
            rpm_head_signing.insert_signature(
                os.path.join(self.tmpdir, "testpkg-%s.noarch.rpm" % pkg),
                os.path.join(self.asset_dir, "testpkg-%s.noarch.rpm.hdr.sig" % pkg),
            )
            res = subprocess.check_output(
                [
                    "rpm",
                    "--define",
                    "%%_keyringpath %s" % self.tmpdir,
                    "--define",
                    "%%_keyringpath %s" % self.tmpdir,
                    "-Kvvvvvvvv",
                    os.path.join(self.tmpdir, "testpkg-%s.noarch.rpm" % pkg),
                ],
            )
            self.assertTrue(b"SHA1 digest: OK" in res)
            self.assertTrue(b"Header V3 RSA" in res)
            self.assertTrue(b"15f712be: ok" in res.lower())

    def test_insert_ima_presigned(self):
        def insert_cb(pkg):
            rpm_head_signing.insert_signature(
                os.path.join(self.tmpdir, "testpkg-%s.noarch.rpm" % pkg),
                os.path.join(self.asset_dir, "testpkg-%s.noarch.rpm.hdr.sig" % pkg),
                ima_presigned_path=os.path.join(self.asset_dir, "digests.out.signed"),
            )

        self._ima_insertion_test(insert_cb, "15f712be")

    def test_insert_ima_presigned_nonhdrsigned(self):
        def insert_cb(pkg):
            rpm_head_signing.insert_signature(
                os.path.join(self.tmpdir, "testpkg-%s.signed.noarch.rpm" % pkg),
                None,
                ima_presigned_path=os.path.join(self.asset_dir, "digests.out.signed"),
            )

        self._ima_insertion_test(insert_cb, "9ab51e50", nonhdrsigned=True)

    def test_insert_ima_valgrind_normal(self):
        self._test_insert_ima_valgrind("normal", "15f712be")

    def test_insert_ima_valgrind_normal_nonhdrsigned(self):
        self._test_insert_ima_valgrind("normal", "9ab51e50", nonhdrsigned=True)

    def test_insert_ima_valgrind_splice_header(self):
        self._test_insert_ima_valgrind("splice_header", "15f712be")

    def test_insert_ima_valgrind_splice_header_nonhdrsigned(self):
        self._test_insert_ima_valgrind("splice_header", "9ab51e50", nonhdrsigned=True)

    def _test_insert_ima_valgrind(self, insert_mode, rpm_keyid, nonhdrsigned=False):
        if os.environ.get("SKIP_VALGRIND"):
            raise unittest.SkipTest("Valgrind tests are disabled")
        valgrind_logfile = os.environ.get(
            "VALGRIND_LOG_FILE",
            "%s/valgrind.log" % self.tmpdir,
        )

        def insert_cb(pkg):
            insert_command = [
                "valgrind",
                "--tool=memcheck",
                "--track-fds=yes",
                "--leak-check=full",
                "--track-origins=yes",
                "--log-file=%s" % valgrind_logfile,
                "--",
                sys.executable,
                "test_insert.py",
                insert_mode,
            ]
            if nonhdrsigned:
                rpm_path = os.path.join(
                    self.tmpdir, "testpkg-%s.signed.noarch.rpm" % pkg
                )
                sig_path = "none"
            else:
                rpm_path = os.path.join(self.tmpdir, "testpkg-%s.noarch.rpm" % pkg)
                sig_path = os.path.join(
                    self.asset_dir, "testpkg-%s.noarch.rpm.hdr.sig" % pkg
                )
            subprocess.check_call(
                insert_command
                + [
                    rpm_path,
                    sig_path,
                    os.path.join(self.asset_dir, "digests.out.signed"),
                ]
            )

        self._ima_insertion_test(insert_cb, rpm_keyid, nonhdrsigned=nonhdrsigned)

        with open(valgrind_logfile, "r") as logfile:
            log = logfile.read()
        if os.environ.get("PRINT_VALGRIND_LOG"):
            print("---- START OF VALGRIND LOG ----")
            print(log)
            print("---- END OF VALGRIND LOG ----")
        if "insertlib.c" in log:
            raise Exception("insertlib.c found in the Valgrind log")

    def _ima_insertion_test(self, insert_command, rpm_keyid, nonhdrsigned=False):
        if nonhdrsigned:
            copy(
                os.path.join(self.asset_dir, "puiterwijk.gpgkey.asc"),
                os.path.join(self.tmpdir, "gpgkey.key"),
            )
        else:
            copy(
                os.path.join(self.asset_dir, "gpgkey.asc"),
                os.path.join(self.tmpdir, "gpgkey.key"),
            )
        for pkg in self.pkg_numbers:
            if nonhdrsigned:
                rpm_filename = "testpkg-%s.signed.noarch.rpm" % pkg
            else:
                rpm_filename = "testpkg-%s.noarch.rpm" % pkg
            copy(
                os.path.join(self.asset_dir, rpm_filename),
                os.path.join(self.tmpdir, rpm_filename),
            )
            res = subprocess.check_output(
                [
                    "rpm",
                    "--define",
                    "%%_keyringpath %s" % self.tmpdir,
                    "--define",
                    "%%_keyringpath %s" % self.tmpdir,
                    "-Kv",
                    os.path.join(self.tmpdir, rpm_filename),
                ],
            )
            self.assertTrue(b"SHA1 digest: OK" in res)
            self.assertFalse(b"Header V3 RSA" in res)

            insert_command(pkg)

            res = subprocess.check_output(
                [
                    "rpm",
                    "--define",
                    "%%_keyringpath %s" % self.tmpdir,
                    "--define",
                    "%%_keyringpath %s" % self.tmpdir,
                    "-Kvvvv",
                    os.path.join(self.tmpdir, rpm_filename),
                ],
            )
            self.assertTrue(b"SHA1 digest: OK" in res)
            msg = ("%s: ok" % rpm_keyid).encode("utf8")
            self.assertTrue(msg in res.lower())

            siginfos = rpm_head_signing.get_rpm_ima_signature_info(
                os.path.join(self.tmpdir, rpm_filename),
            )
            if siginfos is None:
                raise Exception("No IMA signatures found")
            CORRECT_KEY_ID = "379efb19"
            for path in siginfos:
                siginfo = siginfos[path]
                if siginfo["error"]:
                    raise Exception(
                        "Siginfo parsing for path %s resulted in error: %s"
                        % (path, siginfo["error"])
                    )
                if siginfo["user_readable_key_id"] != CORRECT_KEY_ID:
                    raise Exception(
                        "User readable key ID is %s, not %s"
                        % (siginfo["user_readable_key_id"], CORRECT_KEY_ID)
                    )

            extracted_dir = os.path.join(
                self.tmpdir,
                rpm_filename.rstrip(".rpm"),
            )

            os.mkdir(extracted_dir)

            rpm_head_signing.extract_rpm_with_filesigs(
                os.path.join(self.tmpdir, rpm_filename),
                extracted_dir,
            )

            with open(os.path.join(self.asset_dir, "imacert.der"), "rb") as f:
                cert = load_der_x509_certificate(f.read(), backend=default_backend())
                pubkey = cert.public_key()

            evmctl_help = subprocess.check_output(["evmctl", "--help"])

            for (where, dnames, fnames) in os.walk(extracted_dir):
                for fname in fnames:
                    # Always run the manual evmctl check.
                    alternative_evmctl_check(
                        os.path.join(where, fname),
                        pubkey,
                    )

                    if b"--xattr-user" in evmctl_help:
                        subprocess.check_call(
                            [
                                "evmctl",
                                "-v",
                                "--key",
                                os.path.join(self.asset_dir, "imacert.der"),
                                "ima_verify",
                                "--xattr-user",
                                os.path.join(where, fname),
                            ],
                        )
                    else:
                        if not os.environ.get("ONLY_ALTERNATIVE_EVMCTL_CHECK"):
                            raise Exception("Can't test evmctl")


def alternative_evmctl_check(file_path, pubkey):
    # In RHEL7, evmctl is too old, so we won't be able to run the
    #  evmctl check
    ima_sig = bytearray(xattr.getxattr(file_path, "user.ima"))
    ima_sig_info = rpm_head_signing.parse_ima_signature(ima_sig)
    if ima_sig_info["error"]:
        raise Exception("Error parsing IMA signature: %s" % ima_sig_info["error"])
    if ima_sig_info["type"] != 3:
        raise Exception("IMA signature has wrong prefix (%s)" % ima_sig_info["type"])
    if ima_sig_info["version"] != 2:
        raise Exception(
            "IMA signature has wrong version (%s)" % ima_sig_info["version"]
        )
    if sys.version_info.major == 3:
        # X962 is only supported on Cryptography 2.5+
        # We are a bit lazy and just check for py3 instead of checking this more carefully

        # Check the Key ID
        keybytes = pubkey.public_bytes(
            crypto_serialization.Encoding.X962,
            crypto_serialization.PublicFormat.UncompressedPoint,
        )
        # Security explanation: SHA1 is the defined function to use for this.
        # It's bad, but it's what we are supposed to use.
        keybytes_digester = Hash(
            SHA1(),  # nosec
            backend=default_backend(),
        )
        keybytes_digester.update(keybytes)
        keybytes_digest = keybytes_digester.finalize()
        correct_keyid = keybytes_digest[-4:]
        if correct_keyid != ima_sig_info["key_id"]:
            raise Exception(
                "IMA signature has invalid key ID: %s != %s"
                % (correct_keyid, ima_sig_info["key_id"])
            )
    # Check the signature itself
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


if __name__ == "__main__":
    unittest.main()
