#!/usr/bin/env python
import sys

import rpm_head_signing.fix_signatures as fix_signatures

if __name__ == "__main__":
    rpm_path = sys.argv[1]

    print(fix_signatures.fix_ima_signatures(rpm_path, dry_run=False))
