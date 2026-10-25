#!/usr/bin/env python3
"""Offline Android ADB security triage: JSON + HTML, no device changes."""
import argparse
import datetime as dt
import html
import json
import re
from pathlib import Path

LEVELS = {'HIGH': 0, 'MEDIUM': 1, 'REVIEW': 2, 'INFO': 3}
SENSITIVE = {
    'android.permission.INJECT_EVENTS', 'android.permission.CAPTURE_VIDEO_OUTPUT',
    'android.permission.READ_FRAME_BUFFER', 'android.permission.INTERACT_ACROSS_USERS_FULL',
    'android.permission.DELETE_PACKAGES', 'android.permission.READ_PRIVILEGED_PHONE_STATE',
    'android.permission.BIND_ACCESSIBILITY_SERVICE', 'android.permission.MANAGE_DEVICE_ADMINS',
}


def read(root, relative):
    p = root / relative
    return p.read_text(encoding='utf-8', errors='replace').strip() if p.is_file() else None


def analyze(root, today=None):
    today = today or dt.date.today()
    manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    coverage, findings = {}, []

    def get(path):
        value = read(root, path)
        coverage[path] = 'missing' if value is None else 'empty' if not value else 'present'
        return value

    def add(level, code, title, evidence, action):
        findings.append(dict(severity=level, id=code, title=title, evidence=evidence, recommendation=action))

    selinux = get('system/security_enforcing.txt')
    if selinux and selinux.lower() != 'enforcing':
        add('HIGH', 'SELINUX_NOT_ENFORCING', 'SELinux is not enforcing', selinux, 'Check device integrity and intended firmware configuration.')
    boot = get('system/verified_boot.txt')
    if boot and boot.lower() in ('orange', 'red'):
        add('HIGH' if boot.lower() == 'red' else 'MEDIUM', 'VERIFIED_BOOT_' + boot.upper(), 'Verified Boot is ' + boot, boot, 'Check bootloader state and installed OS.')
    lock = get('system/bootloader_state.txt')
    if lock and lock.lower() == 'unlocked':
        add('MEDIUM', 'BOOTLOADER_UNLOCKED', 'Bootloader is unlocked', lock, 'Verify whether this was intentional; do not relock an unsupported custom image.')
    patch = get('system/security_patch.txt')
    if patch:
        try:
            age = (today - dt.date.fromisoformat(patch)).days
            if age > 365:
                add('HIGH', 'PATCH_OVER_YEAR', 'Android security patch older than one year', f'{patch} ({age} days)', 'Consider migrating to a supported device or OS; app hardening cannot patch firmware.')
            elif age > 180:
                add('MEDIUM', 'PATCH_OLD', 'Android security patch older than 180 days', f'{patch} ({age} days)', 'Check official security updates.')
            elif age < -31:
                add('REVIEW', 'PATCH_FUTURE', 'Security patch date appears to be in the future', patch, 'Check build metadata.')
        except ValueError:
            add('REVIEW', 'PATCH_INVALID', 'Security patch cannot be parsed', patch, 'Inspect build properties.')
    if get('security/package_verifier.txt') == '0':
        add('MEDIUM', 'PACKAGE_VERIFIER_DISABLED', 'Package verifier setting is disabled', '0', 'Review Play Protect and installation protection; OEM behavior differs.')
    if get('security/adb_enabled.txt') == '1':
        add('INFO', 'ADB_ENABLED', 'USB debugging enabled', 'adb_enabled=1', 'Disable debugging and revoke authorizations after inspection when no longer needed.')

    for path, code, label in [
        ('security/accessibility.txt', 'ACCESSIBILITY', 'Accessibility services'),
        ('security/notification_listeners.txt', 'NOTIFICATION_LISTENERS', 'Notification listeners')]:
        value = get(path)
        if value and value.lower() not in ('null', 'none', '[]'):
            components = [x.strip() for x in value.split(':') if x.strip()]
            installed = get('apps/packages_user.txt')
            installed_set = set(re.findall(r'^package:([^\s]+)', installed or '', re.M)) if installed is not None else None
            active = [x for x in components if installed_set is None or x.split('/')[0] in installed_set]
            stale = [x for x in components if installed_set is not None and x.split('/')[0] not in installed_set]
            if active:
                add('REVIEW', code, label + ' enabled', '\n'.join(active), 'Check each app and necessity of access; package name is not proof of trust.')
            if stale:
                add('INFO', code + '_STALE', label + ': entries for absent packages', '\n'.join(stale), 'Confirm uninstalled apps; avoid manually editing settings without reason.')
    for path in ('security/device_policy.txt', 'security/vpn.txt', 'security/default_input_method.txt'):
        get(path)

    third = get('apps/packages_third_party.txt')
    packages = []
    if third:
        for line in third.splitlines():
            match = re.search(r'package:([^\s]+)', line)
            if match:
                packages.append({'name': match.group(1), 'installer': (re.search(r'installer=([^\s]+)', line) or [None, 'unknown'])[1]})
    checked = 0
    for item in packages:
        pkg = item['name']
        detail = read(root, 'packages_detail/' + pkg + '_package.txt')
        ops = read(root, 'packages_detail/' + pkg + '_appops.txt')
        if detail is None:
            continue
        checked += 1
        granted = sorted(set(re.findall(r'^\s*([\w.]+): granted=true', detail, re.M)))
        privileged = [p for p in granted if p in SENSITIVE]
        if privileged:
            add('REVIEW', 'PRIVILEGED_' + pkg, 'Sensitive granted permissions: ' + pkg,
                ', '.join(privileged), 'Check the app identity and actual purpose. Granted does not establish active use.')
        if ops and re.search(r'(?m)^\s*(?:SYSTEM_ALERT_WINDOW|WRITE_SETTINGS): allow\b', ops):
            add('REVIEW', 'SPECIAL_ACCESS_' + pkg, 'Special app access: ' + pkg,
                '\n'.join(x for x in ops.splitlines() if re.search(r'(SYSTEM_ALERT_WINDOW|WRITE_SETTINGS): allow', x))[:1200],
                'Confirm overlays / settings modification are needed.')
        if item['installer'] not in ('com.android.vending', 'com.sec.android.app.samsungapps', 'com.samsung.android.app.watchmanager', 'com.samsung.android.app.updatecenter'):
            add('REVIEW', 'INSTALLER_' + pkg, 'Nonstandard or unknown installer: ' + pkg, item['installer'],
                'Verify installation origin and APK signing certificate; nonstandard installer is not malware proof.')
    findings.sort(key=lambda x: (LEVELS[x['severity']], x['id']))
    failures = [c['profile'] + '/' + c['name'] for c in manifest.get('commands', []) if c.get('exit_code') != 0]
    return {'schema_version': 2, 'timestamp': manifest.get('timestamp'), 'report': str(root),
            'coverage': coverage, 'failed_commands': failures,
            'packages_seen': len(packages), 'packages_detailed': checked, 'findings': findings,
            'limitations': ['Triage, not malware detection or forensic proof of absence.',
                            'Vendor firmware and baseband vulnerabilities generally cannot be evaluated by ADB.',
                            'AppOps allow and granted=true do not prove a permission was exercised.',
                            'Package installer is informational, not a cryptographic verification.',
                            'Raw reports and findings can contain personal information. Never publish them.']}


def render_html(result):
    esc = lambda v: html.escape(str(v), quote=True)
    counts = {k: sum(f['severity'] == k for f in result['findings']) for k in LEVELS}
    cards = []
    for f in result['findings']:
        cards.append(f'<article><h3><span class="{esc(f["severity"])}">{esc(f["severity"])}</span> {esc(f["title"])}</h3>'
                     f'<div class="muted">{esc(f["id"])}</div><pre>{esc(f["evidence"])}</pre><p>{esc(f["recommendation"])}</p></article>')
    return f'''<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Android Security Audit</title>
<style>body{{max-width:900px;margin:3rem auto;padding:0 1rem;font:16px system-ui;background:#101723;color:#e9edf3}}article{{border:1px solid #485364;border-radius:12px;padding:1rem;margin:1rem 0;background:#1b2533}}h1,h2{{color:white}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#121923;padding:.8rem;border-radius:6px}}.HIGH{{color:#ff7777}}.MEDIUM{{color:#ffcb75}}.REVIEW{{color:#9ccaff}}.INFO,.muted{{color:#bac4d0}}p{{line-height:1.55}}</style>
<h1>Android Security Audit</h1><p>Scan: {esc(result['timestamp'])} · HIGH {counts['HIGH']} · MEDIUM {counts['MEDIUM']} · REVIEW {counts['REVIEW']} · INFO {counts['INFO']}</p>
<p>Erfasste Drittanbieterpakete: {result['packages_seen']} · Detailliert geprüft: {result['packages_detailed']}. <strong>Kein Malware-Freibrief.</strong></p>
<h2>Findings</h2>{''.join(cards) or '<p>Keine Regel hat ausgelöst; Abdeckung prüfen.</p>'}<h2>Abdeckung und Grenzen</h2>
<p>Fehlgeschlagene Befehle: {len(result['failed_commands'])}.</p><pre>{esc(chr(10).join(result['failed_commands']) or 'Keine')}</pre>
<ul>{''.join('<li>'+esc(x)+'</li>' for x in result['limitations'])}</ul><p><strong>Vertraulich:</strong> Bericht enthält möglicherweise Geräte- und App-Informationen. Nicht öffentlich hochladen.</p></html>'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('report', type=Path)
    args = p.parse_args()
    if not (args.report / 'manifest.json').is_file():
        p.error('manifest.json not found in report')
    result = analyze(args.report)
    dest_json = args.report / 'security_findings.json'
    dest_html = args.report / 'security_report.html'
    dest_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    dest_html.write_text(render_html(result), encoding='utf-8')
    for f in result['findings']:
        print(f'[{f["severity"]:6}] {f["title"]}')
    print(f'Packages: {result["packages_seen"]}, detailed: {result["packages_detailed"]}, failed commands: {len(result["failed_commands"])}')
    print(f'Reports: {dest_html} and {dest_json}')


if __name__ == '__main__':
    main()
