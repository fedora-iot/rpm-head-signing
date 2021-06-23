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
            res = subprocess.check_output(
                [
                    'rpm',
                    '--define', '%%_keyringpath %s' % self.tmpdir,
                    '--define', '%%_keyringpath %s' % self.tmpdir,
                    '-Kv',
                    os.path.join(self.tmpdir, 'testpkg-%s.noarch.rpm' % pkg),
                ],
            )
            print("output: %s" % res)
            self.assertTrue(b'SHA1 digest: OK' in res)
            self.assertFalse(b'Header V3 RSA' in res)
            rpm_head_signing.insert_signature(
                os.path.join(self.tmpdir, 'testpkg-%s.noarch.rpm' % pkg),
                os.path.join(self.asset_dir, 'testpkg-%s.noarch.rpm.hdr.sig' % pkg)
            )
            res = subprocess.check_output(
                [
                    'rpm',
                    '--define', '%%_keyringpath %s' % self.tmpdir,
                    '--define', '%%_keyringpath %s' % self.tmpdir,
                    '-Kvvvvvvvv',
                    os.path.join(self.tmpdir, 'testpkg-%s.noarch.rpm' % pkg),
                ],
            )
            self.assertTrue(b'SHA1 digest: OK' in res)
            self.assertTrue(b'Header V3 RSA' in res)
            self.assertTrue(b'15f712be: ok' in res.lower())

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
            res = subprocess.check_output(
                [
                    'rpm',
                    '--define', '%%_keyringpath %s' % self.tmpdir,
                    '--define', '%%_keyringpath %s' % self.tmpdir,
                    '-Kv',
                    os.path.join(self.tmpdir, 'testpkg-%s.noarch.rpm' % pkg),
                ],
            )
            print("output: %s" % res)
            self.assertTrue(b'SHA1 digest: OK' in res)
            self.assertFalse(b'Header V3 RSA' in res)
            rpm_head_signing.insert_signature(
                os.path.join(self.tmpdir, 'testpkg-%s.noarch.rpm' % pkg),
                os.path.join(self.asset_dir, 'testpkg-%s.noarch.rpm.hdr.sig' % pkg),
                ima_presigned_path=os.path.join(self.asset_dir, 'digests.out.signed'),
            )
            res = subprocess.check_output(
                [
                    'rpm',
                    '--define', '%%_keyringpath %s' % self.tmpdir,
                    '--define', '%%_keyringpath %s' % self.tmpdir,
                    '-Kvvvv',
                    os.path.join(self.tmpdir, 'testpkg-%s.noarch.rpm' % pkg),
                ],
            )
            self.assertTrue(b'SHA1 digest: OK' in res)
            self.assertTrue(b'Header V3 RSA' in res)
            self.assertTrue(b'15f712be: ok' in res.lower())

            extracted_dir = os.path.join(self.tmpdir, 'testpkg-%s.noarch.extracted' % pkg)

            os.mkdir(extracted_dir)

            rpm_head_signing.extract_rpm_with_filesigs(
                os.path.join(self.tmpdir, 'testpkg-%s.noarch.rpm' % pkg),
                extracted_dir,
            )

            with open(os.path.join(self.asset_dir, 'imacert.der'), 'rb') as f:
                cert = load_der_x509_certificate(f.read(), backend=default_backend())
                pubkey = cert.public_key()

            evmctl_help = subprocess.check_output(['evmctl', '--help'])

            for (where, dnames, fnames) in os.walk(extracted_dir):
                for fname in fnames:
                    # Always run the manual evmctl check.
                    alternative_evmctl_check(
                        os.path.join(where, fname),
                        pubkey,
                    )

                    if b'--xattr-user' in evmctl_help:
                        subprocess.check_call(
                            [
                                'evmctl',
                                '-v',
                                '--key', os.path.join(self.asset_dir, 'imacert.der'),
                                'ima_verify',
                                '--xattr-user',
                                os.path.join(where, fname),
                            ],
                        )
                    else:
                        if not os.environ.get('ONLY_ALTERNATIVE_EVMCTL_CHECK'):
                            raise Exception("Can't test evmctl")


def alternative_evmctl_check(file_path, pubkey):
    # In RHEL7, evmctl is too old, so we won't be able to run the
    #  evmctl check
    ima_sig = bytearray(xattr.getxattr(file_path, 'user.ima'))
    if ima_sig[0] != 3:
        raise Exception("IMA signature has wrong prefix (%s)" % ima_sig[0])
    if ima_sig[1] != 2:
        raise Exception("IMA signature has wrong version (%s)" % ima_sig[1])
    algo_id = ima_sig[2]
    if algo_id == 7:  # SHA224
        hasher = hashlib.sha224()
        crypto_algo = crypto_hashes.SHA224()
    elif algo_id == 4:  # SHA256
        hasher = hashlib.sha256()
        crypto_algo = crypto_hashes.SHA256()
    elif algo_id == 5:  # SHA384
        hasher = hashlib.sha384()
        crypto_algo = crypto_hashes.SHA384()
    elif algo_id == 6:  # SHA512
        hasher = hashlib.sha512()
        crypto_algo = crypto_hashes.SHA512()
    else:
        raise Exception("IMA signature has invalid algo: %d" % algo_id)
    crypto_algo = Prehashed(crypto_algo)
    if sys.version_info.major == 3:
        # X962 is only supported on Cryptography 2.5+
        # We are a bit lazy and just check for py3 instead of checking this more carefully

        # Check the Key ID
        key_id = ima_sig[3:7]
        keybytes = pubkey.public_bytes(
            crypto_serialization.Encoding.X962,
            crypto_serialization.PublicFormat.UncompressedPoint,
        )
        keybytes_digester = Hash(SHA1())
        keybytes_digester.update(keybytes)
        keybytes_digest = keybytes_digester.finalize()
        correct_keyid = keybytes_digest[-4:]
        if correct_keyid != key_id:
            raise Exception("IMA signature has invalid key ID: %s != %s" % (correct_keyid, key_id))
    # Check the signature itself
    (sig_size,) = struct.unpack('>H', ima_sig[7:9])
    sig = ima_sig[9:]
    if len(sig) != sig_size:
        raise Exception("IMA signature size invalid: %d != %d" % (len(sig), sig_size))

    with open(file_path, 'rb') as f:
        hasher.update(f.read())
        file_digest = hasher.digest()
    pubkey.verify(
        bytes(sig),
        bytes(file_digest),
        crypto_ec.ECDSA(crypto_algo),
    )


if __name__ == '__main__':
    unittest.main()
