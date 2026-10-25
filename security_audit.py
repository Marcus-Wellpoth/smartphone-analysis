#!/usr/bin/env python3
"""Offline, read-only security triage for adb_inspector.py reports."""
import argparse
import datetime as dt
import json
from pathlib import Path


def read(path):
    try:
        return path.read_text(encoding='utf-8', errors='replace').strip()
    except FileNotFoundError:
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path, help='existing report directory')
    parser.add_argument('--output', type=Path, help='write JSON findings (default: <report>/security_findings.json)')
    args = parser.parse_args()
    root = args.report
    if not (root / 'manifest.json').is_file():
        parser.error('report/manifest.json missing: supply a report created by adb_inspector.py')
    manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    findings = []
    coverage = {}

    def datum(key, profile='security'):
        value = read(root / profile / (key + '.txt'))
        coverage[profile + '/' + key] = 'missing' if value is None else ('empty' if not value else 'present')
        return value

    def finding(level, code, title, evidence, recommendation):
        findings.append({'severity': level, 'id': code, 'title': title,
                         'evidence': evidence, 'recommendation': recommendation})

    selinux = datum('security_enforcing', 'system')
    if selinux and selinux.lower() == 'permissive':
        finding('HIGH', 'SELINUX_PERMISSIVE', 'SELinux is permissive', selinux,
                'Check boot image, rooting status and enterprise/device configuration.')
    elif selinux and selinux.lower() == 'disabled':
        finding('HIGH', 'SELINUX_DISABLED', 'SELinux is disabled', selinux,
                'Investigate device image and system integrity.')

    boot = datum('verified_boot', 'system')
    if boot and boot.lower() in ('orange', 'red'):
        finding('HIGH' if boot.lower() == 'red' else 'MEDIUM', 'VERIFIED_BOOT_' + boot.upper(),
                'Verified Boot state is ' + boot, boot,
                'Check whether the bootloader was intentionally unlocked or the OS modified.')
    elif boot and boot.lower() == 'yellow':
        finding('INFO', 'VERIFIED_BOOT_YELLOW', 'User-configured trust root', boot,
                'Confirm that the custom verified boot key is expected.')

    patch = datum('security_patch', 'system')
    if patch:
        try:
            patch_day = dt.date.fromisoformat(patch)
            age = (dt.datetime.now(dt.timezone.utc).date() - patch_day).days
            if age > 180:
                finding('MEDIUM', 'OLD_SECURITY_PATCH', 'Security patch is more than 180 days old',
                        f'{patch} ({age} days)', 'Check vendor security update availability.')
            elif age < -31:
                finding('INFO', 'FUTURE_PATCH_DATE', 'Reported patch date is unusually far in the future',
                        patch, 'Verify OEM build metadata and device clock.')
        except ValueError:
            finding('INFO', 'PATCH_DATE_INVALID', 'Could not parse patch level', patch,
                    'Check ro.build.version.security_patch manually.')

    adb = datum('adb_enabled')
    if adb == '1':
        finding('INFO', 'ADB_ENABLED', 'USB debugging is enabled', adb,
                'Expected during inspection; disable USB debugging when no longer needed.')

    verifier = datum('package_verifier')
    if verifier == '0':
        finding('MEDIUM', 'PACKAGE_VERIFIER_OFF', 'Package verifier setting is disabled', verifier,
                'Review Android app verification / Play Protect settings; OEM behavior may differ.')

    for key, code, name in [
        ('accessibility', 'ACCESSIBILITY_SERVICES', 'Enabled accessibility services'),
        ('notification_listeners', 'NOTIFICATION_LISTENERS', 'Enabled notification listeners')]:
        value = datum(key)
        if value and value.lower() not in ('null', 'none', '[]'):
            finding('REVIEW', code, name, value[:4000],
                    'Verify every listed app is trusted and requires this level of access.')

    for key in ('device_policy', 'vpn', 'development_settings', 'install_non_market_apps'):
        datum(key)
    levels = {'HIGH': 0, 'MEDIUM': 1, 'REVIEW': 2, 'INFO': 3}
    findings.sort(key=lambda f: (levels[f['severity']], f['id']))
    result = {'schema_version': 1, 'report': str(root), 'device_serial': manifest.get('serial'),
              'coverage': coverage, 'findings': findings,
              'limitations': [
                  'Triage only: not a malware verdict and not a complete forensic acquisition.',
                  'Missing commands and OEM differences prevent negative assurance.',
                  'A finding may be legitimate in a development, rooted or managed device.',
                  'Output contains device-specific details; never commit audit reports to Git.'
              ]}
    output = args.output or root / 'security_findings.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(f'Security triage: {len(findings)} finding(s)')
    for item in findings:
        print(f"[{item['severity']:<6}] {item['id']}: {item['title']}")
    missing = [k for k, v in coverage.items() if v == 'missing']
    if missing:
        print('Not collected: ' + ', '.join(missing))
    print(f'JSON: {output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
