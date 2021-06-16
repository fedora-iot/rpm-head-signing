from tempfile import mkdtemp
from shutil import rmtree, copy
import os.path
import subprocess
import unittest

import rpm_head_signing

class TestRpmHeadSigning(unittest.TestCase):
    pkg_numbers = ['1', '2']

    @classmethod
    def setUpClass(cls):
        cls.asset_dir = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'test_assets',
        )

    def setUp(self):
        self.tmpdir = mkdtemp(prefix='test-rpm_head_signing-', dir=os.path.abspath('.'))

    def tearDown(self):
        rmtree(self.tmpdir)
        self.tmpdir = None

    def compare_files(self, asset_name, tmp_name):
        with open(os.path.join(self.asset_dir, asset_name), 'rb') as asset_file:
            with open(os.path.join(self.tmpdir, tmp_name), 'rb') as tmp_file:
                self.assertEqual(
                    asset_file.read(),
                    tmp_file.read(),
                    "Asset file %s is different from tmp file %s" % (asset_name, tmp_name),
                )

    def test_extract(self):
        rpm_head_signing.extract_header(
            os.path.join(self.asset_dir, 'testpkg-1.noarch.rpm'),
            os.path.join(self.tmpdir, 'testpkg-1.noarch.rpm.hdr.tmp'),
            os.path.join(self.tmpdir, 'digests.out.tmp'),
        )
        rpm_head_signing.extract_header(
            os.path.join(self.asset_dir, 'testpkg-2.noarch.rpm'),
            os.path.join(self.tmpdir, 'testpkg-2.noarch.rpm.hdr.tmp'),
            os.path.join(self.tmpdir, 'digests.out.tmp'),
        )

        self.compare_files("testpkg-1.noarch.rpm.hdr", "testpkg-1.noarch.rpm.hdr.tmp")
        self.compare_files("testpkg-2.noarch.rpm.hdr", "testpkg-2.noarch.rpm.hdr.tmp")
        self.compare_files("digests.out", "digests.out.tmp")

    def test_insert_no_ima(self):
        copy(
            os.path.join(self.asset_dir, 'gpgkey.asc'),
            os.path.join(self.tmpdir, 'gpgkey.key'),
        )
        for pkg in self.pkg_numbers:
            copy(
                os.path.join(self.asset_dir, "testpkg-%s.noarch.rpm" % pkg),
                os.path.join(self.tmpdir, "testpkg-%s.noarch.rpm" % pkg),
            )
            res = subprocess.run(
                [
                    'rpm',
                    '--define', '%%_keyringpath %s' % self.tmpdir,
                    '--define', '%%_keyringpath %s' % self.tmpdir,
                    '-Kv',
                    os.path.join(self.tmpdir, 'testpkg-%s.noarch.rpm' % pkg),
                ],
                check=True,
                capture_output=True,
                encoding='utf-8',
            )
            self.assertTrue('SHA256 digest: OK' in res.stdout)
            self.assertFalse('Header V3 RSA' in res.stdout)
            rpm_head_signing.insert_signature(
                os.path.join(self.tmpdir, 'testpkg-%s.noarch.rpm' % pkg),
                os.path.join(self.asset_dir, 'testpkg-%s.noarch.rpm.hdr.sig' % pkg)
            )
            res = subprocess.run(
                [
                    'rpm',
                    '--define', '%%_keyringpath %s' % self.tmpdir,
                    '--define', '%%_keyringpath %s' % self.tmpdir,
                    '-Kvvvvvvvv',
                    os.path.join(self.tmpdir, 'testpkg-%s.noarch.rpm' % pkg),
                ],
                check=True,
                capture_output=True,
                encoding='utf-8',
            )
            self.assertTrue('SHA256 digest: OK' in res.stdout)
            self.assertTrue('Header V3 RSA' in res.stdout)
            self.assertTrue('15f712be: ok' in res.stdout.lower())

    def test_insert_ima(self):
        copy(
            os.path.join(self.asset_dir, 'gpgkey.asc'),
            os.path.join(self.tmpdir, 'gpgkey.key'),
        )
        for pkg in self.pkg_numbers:
            copy(
                os.path.join(self.asset_dir, "testpkg-%s.noarch.rpm" % pkg),
                os.path.join(self.tmpdir, "testpkg-%s.noarch.rpm" % pkg),
            )
            res = subprocess.run(
                [
                    'rpm',
                    '--define', '%%_keyringpath %s' % self.tmpdir,
                    '--define', '%%_keyringpath %s' % self.tmpdir,
                    '-Kv',
                    os.path.join(self.tmpdir, 'testpkg-%s.noarch.rpm' % pkg),
                ],
                check=True,
                capture_output=True,
                encoding='utf-8',
            )
            self.assertTrue('SHA256 digest: OK' in res.stdout)
            self.assertFalse('Header V3 RSA' in res.stdout)
            rpm_head_signing.insert_signature(
                os.path.join(self.tmpdir, 'testpkg-%s.noarch.rpm' % pkg),
                os.path.join(self.asset_dir, 'testpkg-%s.noarch.rpm.hdr.sig' % pkg),
                ima_presigned_path=os.path.join(self.asset_dir, 'digests.out.signed'),
            )
            res = subprocess.run(
                [
                    'rpm',
                    '--define', '%%_keyringpath %s' % self.tmpdir,
                    '--define', '%%_keyringpath %s' % self.tmpdir,
                    '-Kvvvv',
                    os.path.join(self.tmpdir, 'testpkg-%s.noarch.rpm' % pkg),
                ],
                check=True,
                capture_output=True,
                encoding='utf-8',
            )
            self.assertTrue('SHA256 digest: OK' in res.stdout)
            self.assertTrue('Header V3 RSA' in res.stdout)
            self.assertTrue('15f712be: ok' in res.stdout.lower())

            extracted_dir = os.path.join(self.tmpdir, 'testpkg-%s.noarch.extracted' % pkg)

            os.mkdir(extracted_dir)

            rpm_head_signing.extract_rpm_with_filesigs(
                os.path.join(self.tmpdir, 'testpkg-%s.noarch.rpm' % pkg),
                extracted_dir,
            )

            for (where, dnames, fnames) in os.walk(extracted_dir):
                for fname in fnames:
                    subprocess.run(
                        [
                            'evmctl',
                            '-v',
                            '--key', os.path.join(self.asset_dir, 'imacert.der'),
                            'ima_verify',
                            '--xattr-user',
                            os.path.join(where, fname),
                        ],
                        check=True,
                    )


if __name__ == '__main__':
    unittest.main()
