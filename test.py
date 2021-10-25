from tempfile import mkdtemp
from shutil import rmtree, copy
import os
import os.path
import subprocess
import sys
import unittest

import rpm_head_signing
import rpm_head_signing.fix_signatures
import rpm_head_signing.verify_rpm


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
        copy(
            os.path.join(self.asset_dir, "testpkg-1.rpm"),
            os.path.join(self.tmpdir, "testpkg-1.input.rpm"),
        )
        copy(
            os.path.join(self.asset_dir, "testpkg-2.rpm"),
            os.path.join(self.tmpdir, "testpkg-2.input.rpm"),
        )
        rpm_head_signing.extract_header(
            os.path.join(self.tmpdir, "testpkg-1.input.rpm"),
            os.path.join(self.tmpdir, "testpkg-1.rpm.hdr.tmp"),
            os.path.join(self.tmpdir, "digests.out.tmp"),
        )
        rpm_head_signing.extract_header(
            os.path.join(self.tmpdir, "testpkg-2.input.rpm"),
            os.path.join(self.tmpdir, "testpkg-2.rpm.hdr.tmp"),
            os.path.join(self.tmpdir, "digests.out.tmp"),
        )

        self.compare_files("testpkg-1.rpm", "testpkg-1.input.rpm")
        self.compare_files("testpkg-2.rpm", "testpkg-2.input.rpm")
        self.compare_files("testpkg-1.rpm.hdr", "testpkg-1.rpm.hdr.tmp")
        self.compare_files("testpkg-2.rpm.hdr", "testpkg-2.rpm.hdr.tmp")
        self.compare_files("digests.out", "digests.out.tmp")

    def test_extract_no_digests(self):
        rpm_head_signing.extract_header(
            os.path.join(self.asset_dir, "testpkg-1.rpm"),
            os.path.join(self.tmpdir, "testpkg-1.rpm.hdr.tmp"),
            digest_out_path=None,
        )
        rpm_head_signing.extract_header(
            os.path.join(self.asset_dir, "testpkg-2.rpm"),
            os.path.join(self.tmpdir, "testpkg-2.rpm.hdr.tmp"),
            digest_out_path=None,
        )

        self.compare_files("testpkg-1.rpm.hdr", "testpkg-1.rpm.hdr.tmp")
        self.compare_files("testpkg-2.rpm.hdr", "testpkg-2.rpm.hdr.tmp")

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

        result = rpm_head_signing.determine_rpm_status(
            os.path.join(
                self.asset_dir, "sblim-cim-client-javadoc-1.3.9.1-1.el6.noarch.rpm"
            )
        )
        self.assertFalse(result.is_head_only_signable)
        self.assertFalse(result.is_head_only_signed)
        self.assertTrue(result.is_signed)
        self.assertFalse(result.is_ima_signed)

    def test_insert_no_ima(self):
        self._add_gpg_key("gpgkey.asc")
        for pkg in self.pkg_numbers:
            copy(
                os.path.join(self.asset_dir, "testpkg-%s.rpm" % pkg),
                os.path.join(self.tmpdir, "testpkg-%s.rpm" % pkg),
            )
            res = subprocess.check_output(
                [
                    "rpm",
                    "--dbpath",
                    self.tmpdir,
                    "-Kv",
                    os.path.join(self.tmpdir, "testpkg-%s.rpm" % pkg),
                ],
            )
            self.assertTrue(b"SHA1 digest: OK" in res)
            self.assertFalse(b"Header V3 RSA" in res)
            rpm_head_signing.insert_signature(
                os.path.join(self.tmpdir, "testpkg-%s.rpm" % pkg),
                os.path.join(self.asset_dir, "testpkg-%s.rpm.hdr.sig" % pkg),
            )
            res = subprocess.check_output(
                [
                    "rpm",
                    "--dbpath",
                    self.tmpdir,
                    "-Kv",
                    os.path.join(self.tmpdir, "testpkg-%s.rpm" % pkg),
                ],
            )
            self.assertTrue(b"SHA1 digest: OK" in res)
            self.assertTrue(b"Header V3 RSA" in res)
            self.assertTrue(b"15f712be: ok" in res.lower())

            result = rpm_head_signing.determine_rpm_status(
                os.path.join(self.tmpdir, "testpkg-%s.rpm" % pkg)
            )
            self.assertTrue(result.is_head_only_signable)
            self.assertTrue(result.is_head_only_signed)
            self.assertTrue(result.is_signed)
            self.assertFalse(result.is_ima_signed)

    def test_insert_ima_presigned(self):
        def insert_cb(pkg):
            rpm_head_signing.insert_signature(
                os.path.join(self.tmpdir, "testpkg-%s.rpm" % pkg),
                os.path.join(self.asset_dir, "testpkg-%s.rpm.hdr.sig" % pkg),
                ima_presigned_path=os.path.join(self.asset_dir, "digests.out.signed"),
            )

        self._ima_insertion_test(insert_cb, "15f712be")

    def test_insert_ima_presigned_nonhdrsigned(self):
        def insert_cb(pkg):
            rpm_head_signing.insert_signature(
                os.path.join(self.tmpdir, "testpkg-%s.signed.rpm" % pkg),
                None,
                ima_presigned_path=os.path.join(self.asset_dir, "digests.out.signed"),
            )

        self._ima_insertion_test(insert_cb, "9ab51e50", nonhdrsigned=True)

    def test_insert_ima_byteorder_wrong(self):
        copy(
            os.path.join(self.asset_dir, "centos-stream-release-9.0-1.c9s.noarch.rpm"),
            os.path.join(self.tmpdir, "centos-stream-release-9.0-1.c9s.noarch.rpm"),
        )
        rpm_head_signing.insert_signature(
            os.path.join(self.tmpdir, "centos-stream-release-9.0-1.c9s.noarch.rpm"),
            None,
            os.path.join(self.asset_dir, "centos-stream.ima.digests.signed"),
        )

        if os.environ.get("SKIP_BYTEORDER_CHECK"):
            raise unittest.SkipTest(
                "Skipping remainer of byteorder test due to RPM bug"
            )
        siginfos = rpm_head_signing.get_rpm_ima_signature_info(
            os.path.join(self.tmpdir, "centos-stream-release-9.0-1.c9s.noarch.rpm"),
        )
        for path in siginfos:
            sig = siginfos[path]
            self.assertEqual(
                sig["error"],
                None,
                "Signature for %s had an error: %s" % (path, sig["error"]),
            )

    def test_verify_rpm(self):
        # This is a negative test (on the unsigned RPM) to ensure verify_rpm is
        # working as expected.
        args = self._get_verify_rpm_args()
        args.extend([os.path.join(self.asset_dir, "testpkg-1.rpm")])

        args = rpm_head_signing.verify_rpm.get_args().parse_args(args)
        self.assertFalse(rpm_head_signing.verify_rpm.main(args))

    def test_fix_signatures(self):
        return True
        pkgname = "readline-8.1-4.el9.i686.rpm"
        copy(
            os.path.join(self.asset_dir, pkgname),
            os.path.join(self.tmpdir, pkgname),
        )
        result = rpm_head_signing.fix_signatures.fix_ima_signatures(
            os.path.join(self.tmpdir, pkgname),
            dry_run=True,
        )
        self.assertEqual(result, rpm_head_signing.fix_signatures.CHANGED_IMA_SIG_LENGTH)
        # We did a dry-run, this should not have changed the RPM
        self.compare_files(
            os.path.join(self.asset_dir, pkgname),
            os.path.join(self.tmpdir, pkgname),
        )
        result = rpm_head_signing.fix_signatures.fix_ima_signatures(
            os.path.join(self.tmpdir, pkgname),
            dry_run=False,
        )
        self.assertEqual(result, rpm_head_signing.fix_signatures.CHANGED_IMA_SIG_LENGTH)
        # Now we did an actual fix, so re-running the fixer should return no changes
        result = rpm_head_signing.fix_signatures.fix_ima_signatures(
            os.path.join(self.tmpdir, pkgname),
            dry_run=True,
        )
        self.assertEqual(result, rpm_head_signing.fix_signatures.CHANGED_NONE)
        res = subprocess.Popen(
            [
                "rpm",
                "--dbpath",
                self.tmpdir,
                "-Kv",
                os.path.join(self.tmpdir, pkgname),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        res = res.communicate()[0]
        self.assertTrue(b"SHA1 digest: OK" in res)
        self.assertTrue(b"Header V3 RSA" in res)
        rpm_head_signing.get_rpm_ima_signature_info(
            os.path.join(self.tmpdir, pkgname),
        )

    def test_fix_signatures_valgrind(self):
        return True
        pkgname = "readline-8.1-4.el9.i686.rpm"
        copy(
            os.path.join(self.asset_dir, pkgname),
            os.path.join(self.tmpdir, pkgname),
        )
        cmd = [sys.executable, "test_fix.py", os.path.join(self.tmpdir, pkgname)]
        result = rpm_head_signing.fix_signatures.fix_ima_signatures(
            os.path.join(self.tmpdir, pkgname),
            dry_run=True,
        )
        self.assertEqual(result, rpm_head_signing.fix_signatures.CHANGED_IMA_SIG_LENGTH)
        # We did a dry-run, this should not have changed the RPM
        self.compare_files(
            os.path.join(self.asset_dir, pkgname),
            os.path.join(self.tmpdir, pkgname),
        )
        self._run_with_valgrind(cmd + ["active"])
        self._check_valgrind_log()
        # Now we did an actual fix, so re-running the fixer should return no changes
        result = rpm_head_signing.fix_signatures.fix_ima_signatures(
            os.path.join(self.tmpdir, pkgname),
            dry_run=True,
        )
        self.assertEqual(result, rpm_head_signing.fix_signatures.CHANGED_NONE)

    def test_insert_ima_valgrind_normal(self):
        self._test_insert_ima_valgrind("normal", "15f712be")

    def test_insert_ima_valgrind_normal_nonhdrsigned(self):
        self._test_insert_ima_valgrind("normal", "9ab51e50", nonhdrsigned=True)

    def test_insert_ima_valgrind_splice_header(self):
        self._test_insert_ima_valgrind("splice_header", "15f712be")

    def test_insert_ima_valgrind_splice_header_nonhdrsigned(self):
        self._test_insert_ima_valgrind("splice_header", "9ab51e50", nonhdrsigned=True)

    def _run_with_valgrind(self, command):
        if os.environ.get("SKIP_VALGRIND"):
            raise unittest.SkipTest("Valgrind tests are disabled")
        self.valgrind_logfile = os.environ.get(
            "VALGRIND_LOG_FILE",
            "%s/valgrind.log" % self.tmpdir,
        )
        cmd = [
            "valgrind",
            "--tool=memcheck",
            "--track-fds=yes",
            "--leak-check=full",
            "--track-origins=yes",
            "--log-file=%s" % self.valgrind_logfile,
            "--",
        ] + command
        subprocess.check_call(cmd)

    def _check_valgrind_log(self):
        with open(self.valgrind_logfile, "r") as logfile:
            log = logfile.read()
        if os.environ.get("PRINT_VALGRIND_LOG"):
            print("---- START OF VALGRIND LOG ----")
            print(log)
            print("---- END OF VALGRIND LOG ----")
        if "insertlib.c" in log:
            if os.environ.get("VALGRIND_ALLOW_INSERTLIB"):
                print(
                    "Would normally have failed the test due to insertlib.c found in valgrind log"
                )
            else:
                raise Exception("insertlib.c found in the Valgrind log")

    def _test_insert_ima_valgrind(self, insert_mode, rpm_keyid, nonhdrsigned=False):
        def insert_cb(pkg):
            insert_command = [
                sys.executable,
                "test_insert.py",
                insert_mode,
            ]
            if nonhdrsigned:
                rpm_path = os.path.join(self.tmpdir, "testpkg-%s.signed.rpm" % pkg)
                sig_path = "none"
            else:
                rpm_path = os.path.join(self.tmpdir, "testpkg-%s.rpm" % pkg)
                sig_path = os.path.join(self.asset_dir, "testpkg-%s.rpm.hdr.sig" % pkg)
            self._run_with_valgrind(
                insert_command
                + [
                    rpm_path,
                    sig_path,
                    os.path.join(self.asset_dir, "digests.out.signed"),
                ]
            )

        self._ima_insertion_test(insert_cb, rpm_keyid, nonhdrsigned=nonhdrsigned)

        self._check_valgrind_log()

    def _add_gpg_key(self, key_file_name):
        subprocess.check_call(
            [
                "rpm",
                "--dbpath",
                self.tmpdir,
                "--import",
                os.path.join(self.asset_dir, key_file_name),
            ]
        )

    def _ima_insertion_test(self, insert_command, rpm_keyid, nonhdrsigned=False):
        if nonhdrsigned:
            self._add_gpg_key("puiterwijk.gpgkey.asc")
        else:
            self._add_gpg_key("gpgkey.asc")

        rpm_paths = []
        for pkg in self.pkg_numbers:
            if nonhdrsigned:
                rpm_filename = "testpkg-%s.signed.rpm" % pkg
            else:
                rpm_filename = "testpkg-%s.rpm" % pkg
            copy(
                os.path.join(self.asset_dir, rpm_filename),
                os.path.join(self.tmpdir, rpm_filename),
            )
            rpm_paths.append(os.path.join(self.tmpdir, rpm_filename))
            res = subprocess.check_output(
                [
                    "rpm",
                    "--dbpath",
                    self.tmpdir,
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
                    "--dbpath",
                    self.tmpdir,
                    "-Kv",
                    os.path.join(self.tmpdir, rpm_filename),
                ],
            )
            self.assertTrue(b"SHA1 digest: OK" in res)
            msg = ("%s: ok" % rpm_keyid).encode("utf8")
            self.assertTrue(msg in res.lower())

            result = rpm_head_signing.determine_rpm_status(
                os.path.join(self.tmpdir, rpm_filename)
            )
            self.assertTrue(result.is_head_only_signable)
            self.assertTrue(result.is_head_only_signed)
            self.assertTrue(result.is_signed)
            self.assertTrue(result.is_ima_signed)

        # Construct the arguments to verify_rpm
        args = self._get_verify_rpm_args()
        args.extend(rpm_paths)

        args = rpm_head_signing.verify_rpm.get_args().parse_args(args)
        self.assertTrue(rpm_head_signing.verify_rpm.main(args))

    def _get_verify_rpm_args(self):
        args = []

        args.extend(
            [
                "--tmp-path-dir",
                self.tmpdir,
                "--cert-path",
                os.path.join(self.asset_dir, "imacert.der"),
            ],
        )

        if sys.version_info.major != 3:
            # X962 is only supported on Cryptography 2.5+
            # We are a bit lazy and just check for py3 instead of checking
            # this more carefully
            args.append("--skip-keyid-check")

        if os.environ.get("SKIP_IMA_LIVE_CHECK"):
            args.append("--lite-verify")

        evmctl_help = subprocess.check_output(["evmctl", "--help"])
        if b"--xattr-user" not in evmctl_help:
            if not os.environ.get("ONLY_ALTERNATIVE_EVMCTL_CHECK"):
                raise Exception("Can't test evmctl")
            args.append("--skip-evmctl")

        return args


if __name__ == "__main__":
    unittest.main()
