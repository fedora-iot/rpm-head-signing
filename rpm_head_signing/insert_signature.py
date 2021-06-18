#!/usr/bin/env python
import base64
import binascii
import subprocess
from tempfile import mkdtemp
import os.path
import shutil
import struct

import six
import koji

from .extract_header import _get_filedigests
from .extract_rpm_with_filesigs import (
    RPMSIGTAG_FILESIGNATURES,
    RPMSIGTAG_FILESIGNATURELENGTH,
    RPMSIGTAG_RESERVEDSPACE,
    RPMSIGTAG_RSAHEADER,
)

LOOKUP_PATH = '/usr/lib64/ima_lookup.so'

RPM_INT32_TYPE = 4
RPM_BIN_TYPE = 7
RPM_STRING_ARRAY_TYPE = 8


def _insert_signature_with_rpmsign(rpm_path, sig_path, ima_lookup_path=None, ima_presigned_path=None):
    if ima_lookup_path is None:
        ima_lookup_path = LOOKUP_PATH

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
        env = {}
        if ima_presigned_path is not None:
            env['LD_PRELOAD'] = ima_lookup_path
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
            env=env,
        )
    finally:
        if ima_presigned_tempdir:
            shutil.rmtree(ima_presigned_tempdir, ignore_errors=True)


def _insert_signature_custom(rpm_path, sig_path, ima_presigned_path=None):
    sighdr_raw = koji.rip_rpm_sighdr(rpm_path)
    sighdr_len = len(sighdr_raw)
    sighdr_il = struct.unpack('!I', sighdr_raw[8:12])

    sig_records = []

    reserved_space = None

    # Get original records
    for tag in sighdr.index:
        _tag, typ, offset, count = sighdr.index[tag]
        if tag == RPMSIGTAG_RESERVEDSPACE:
            reserved_space = count
            continue
        sig_records.append({
            'tag': tag,
            'type': typ,
            'orig_offset': offset,
            'orig_count': count,
        })

    # Add RSA Header record
    with open(sig_path, 'rb') as sigfile:
        signature = sigfile.read()
        sig_records.append({
            'tag': RPMSIGTAG_RSAHEADER,
            'type': RPM_BIN_TYPE,
            'value': signature,
            'count': len(signature),
        })

    # Add IMA signature record
    if ima_presigned_path is not None:
        ima_signature_lookup = {}
        with open(ima_presigned_path, 'r', encoding='utf8') as sigpath:
            for line in sigpath.readlines():
                algo, digest, signature = line.strip().split(' ')
                signature = binascii.hexlify(base64.b64decode(signature))
                ima_signature_lookup['%s:%s' % (algo, digest)] = signature

        rpmhdr = koji.get_rpm_header(rpm_path)
        file_digestalgo, file_digests = _get_filedigests(rpmhdr)
        ima_signatures = []
        for digest in file_digests:
            signature = ima_signature_lookup.get('%s:%s' % (file_digestalgo, digest))
            if signature is None:
                raise Exception("File digest %s did not have a signature" % digest)
            ima_signatures.append(signature)

        if ima_signatures:
            #sig_records[RPMSIGTAG_FILESIGNATURES] = {
            #    'type': RPM_STRING_ARRAY_TYPE,
            #    'value': b'\0'.join(ima_signatures) + b'\0',
            #    'count': len(ima_signatures),
            #}
            ima_siglen = int((len(ima_signatures[0]) / 2) + 1)
            #sig_records[RPMSIGTAG_FILESIGNATURELENGTH] = {
            #    'type': RPM_INT32_TYPE,
            #    'value': struct.pack('!i', ima_siglen),
            #    'count': 1,
            #}

    # Rebuild the new signature header
    prefix = sighdr_raw[0:8]
    idxs = []
    payloads = []

    orig_store = 16 + len(sighdr.index) * 16
    payload_offset = 0

    for data in sig_records:
        tag = data['tag']
        typ = data['type']

        if 'value' in data:
            payload = data['value']
            payload_count = data['count']
        else:
            offset = data['orig_offset']
            count = data['orig_count']
            if typ == 0:
                # NULL entry
                payload = b''
                payload_count = 1
            elif typ >= 2 and typ <= 5:
                # Integer
                n = 1 << (typ - 2)
                payload = sighdr_raw[orig_store + offset : orig_store + offset + (n * count)]
                payload_count = count
            elif type == 1 or typ == 7:
                # Count-identified size
                payload = sighdr_raw[orig_store + offset : orig_store + offset + count]
                payload_count = count
            elif typ == 6:
                # Null-terminated string
                end = sighdr_raw.find(six.b('\0'), orig_store + offset)
                payload = sighdr_raw[orig_store + offset : orig_store + end]
                payload_count = 1
            else:
                raise NotImplementedError("Tag type %d not implemented" % typ)

        payloads.append(payload)

        idxs.append(
            struct.pack('!IIII', tag, typ, payload_offset, payload_count)
        )
        payload_offset += len(payload)

    # Construct full header
    idx = b''.join(idxs)
    payload = b''.join(payloads)
    hdr_sizes = struct.pack('!II', len(idxs), len(payload))
    sighdr_new = prefix + hdr_sizes + idx + payload
    padding = len(sighdr_new) % 8
    if padding > 0:
        sighdr_new += b'\0' * (8 - padding)

    print("Rest: %d" % (len(sighdr_new) % 8))

    # Check
    data = sighdr_new[8:]
    il = koji.multibyte(data[0:4])
    dl = koji.multibyte(data[4:8])
    hdrsize = 8 + 16 * il + dl
    hdrsize = hdrsize + (8 - (hdrsize % 8)) % 8
    hdrsize = hdrsize + 8

    print("Computed hdrsize: %d, actual size: %d" % (hdrsize, len(sighdr_new)))

    # TODO: Remove
    print("Original: (%s, %s)" % (sighdr.version(), len(sighdr.index)))
    print("raw sizes: %s" % sighdr_raw[8:16])
    print("Interpreted: %d, %d" % struct.unpack('!II', sighdr_raw[8:16]))
    sighdr.dump()

    parsed_new = koji.RawHeader(sighdr_new)
    print("New: (%s, %s)" % (parsed_new.version(), len(parsed_new.index)))
    print("raw sizes: %s" % sighdr_new[8:16])
    print("Interpreted: %d, %d" % struct.unpack('!II', sighdr_new[8:16]))
    parsed_new.dump()


    dst = koji.splice_rpm_sighdr(sighdr_new, rpm_path)
    shutil.move(dst, rpm_path)


def insert_signature(rpm_path, sig_path, ima_lookup_path=None, ima_presigned_path=None, use_rpmsign=None):
    if (ima_lookup_path is not None and use_rpmsign is None) or use_rpmsign is True:
        return _insert_signature_with_rpmsign(
            rpm_path=rpm_path,
            sig_path=sig_path,
            ima_lookup_path=ima_lookup_path,
            ima_presigned_path=ima_presigned_path,
        )
    else:
        return _insert_signature_custom(
            rpm_path=rpm_path,
            sig_path=sig_path,
            ima_presigned_path=ima_presigned_path,
        )


if __name__ == '__main__':
    import sys

    if len(sys.argv) == 3:
        ima_lookup_path = None
        ima_presigned_path = None
    elif len(sys.argv) == 5:
        ima_lookup_path = sys.argv[3]
        if ima_lookup_path.lower() in ['-', 'none']:
            ima_lookup_path = None
        ima_presigned_path = sys.argv[4]
    else:
        raise Exception("Call: %s <rpm-path> <header-signature> [ima_lookup.so_path] [ima_presigned_directory]")

    insert_signature(sys.argv[1], sys.argv[2], ima_lookup_path, ima_presigned_path)
