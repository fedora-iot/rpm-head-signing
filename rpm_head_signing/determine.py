import rpm
from koji import (
    find_rpm_sighdr,
    rpm_hdr_size,
    RawHeader,
    get_header_fields,
)

from .extract_header import RPMTAG_PAYLOADDIGEST
from .extract_rpm_with_filesigs import (
    RPMSIGTAG_FILESIGNATURES,
    _get_header_type_8,
)


class DetermineResult(object):
    is_head_only_signable = None
    is_head_only_signed = None
    is_signed = None
    is_ima_signed = None


def determine_rpm_status(rpm_path):
    (sig_start, sig_size) = find_rpm_sighdr(rpm_path)
    hdr_start = sig_start + sig_size
    hdr_size = rpm_hdr_size(rpm_path, hdr_start)

    with open(rpm_path, "rb") as f:
        f.seek(sig_start)
        sighdr = f.read(sig_size)
        sighdr = RawHeader(sighdr)
        f.seek(hdr_start)
        hdr = f.read(hdr_size)
        hdr = RawHeader(hdr)

    fields = get_header_fields(
        rpm_path,
        (
            "name",
            "basenames",
            "siggpg",
            "sigpgp",
            "rsaheader",
            "dsaheader",
        ),
    )

    filesignatures = sighdr.index.get(RPMSIGTAG_FILESIGNATURES)
    if filesignatures is None and len(fields["basenames"]) == 0:
        filesignatures = True
    elif filesignatures:
        filesigs = _get_header_type_8(sighdr, RPMSIGTAG_FILESIGNATURES)
        if len(filesigs) != len(fields["basenames"]):
            raise ValueError(
                "Invalid RPM encountered: number of IMA signatures doesn't match number of files: %s != %s (%s, %s)"
                % (
                    len(filesigs),
                    len(fields["basenames"]),
                    filesigs,
                    fields["basenames"],
                )
            )
    payloaddigest = hdr.index.get(RPMTAG_PAYLOADDIGEST)

    result = DetermineResult()
    result.is_head_only_signable = payloaddigest is not None
    result.is_head_only_signed = (
        (fields["rsaheader"] is not None or fields["dsaheader"] is not None)
        and fields["siggpg"] is None
        and fields["sigpgp"] is None
    )
    result.is_signed = (
        fields["rsaheader"] is not None
        or fields["dsaheader"] is not None
        or fields["siggpg"] is not None
        or fields["sigpgp"] is not None
    )
    result.is_ima_signed = filesignatures is not None

    return result
