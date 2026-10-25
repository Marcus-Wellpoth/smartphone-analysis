#!/usr/bin/env python3
"""Compare key plain-text ADB inspection results between two report directories."""
import argparse
import difflib
from pathlib import Path

FILES = ['apps/packages_third_party.txt', 'apps/packages_disabled.txt',
         'apps/accessibility.txt', 'apps/notification_listeners.txt',
         'security/device_policy.txt', 'network/private_dns_mode.txt',
         'network/private_dns_specifier.txt', 'system/security_patch.txt']

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('old', type=Path)
    p.add_argument('new', type=Path)
    p.add_argument('--all', action='store_true', help='compare every matching .txt file')
    args = p.parse_args()
    files = sorted({str(x.relative_to(args.old)) for x in args.old.rglob('*.txt')}
                   | {str(x.relative_to(args.new)) for x in args.new.rglob('*.txt')}) if args.all else FILES
    for rel in files:
        old = args.old / rel
        new = args.new / rel
        a = old.read_text(errors='replace').splitlines(keepends=True) if old.exists() else []
        b = new.read_text(errors='replace').splitlines(keepends=True) if new.exists() else []
        if a != b:
            print(''.join(difflib.unified_diff(a, b, fromfile=str(old), tofile=str(new))), end='')

if __name__ == '__main__':
    main()
