from .insertlib import fix_ima_signatures as insertlib_fix_ima_signatures


CHANGED_NONE = 0
CHANGED_IMA_SIG_BYTEORDER = 1 << 0
CHANGED_IMA_SIG_LENGTH = 1 << 1

CHANGED_ALL = CHANGED_IMA_SIG_BYTEORDER | CHANGED_IMA_SIG_LENGTH


def fix_ima_signatures(rpm_path, dry_run=False, to_perform=CHANGED_ALL):
    """
    Fix some errors in IMA signatures.

    This fixes the problem where the IMA signature size header value is missing
    or where the signature size has the incorrect endianness.
    It returns an integer indicating what it fixed.
    """
    return insertlib_fix_ima_signatures(rpm_path, dry_run, to_perform)
