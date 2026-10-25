#!/usr/bin/env python3
"""Read-only Android diagnostics via ADB (Python standard library)."""
import argparse
import datetime as dt
import json
import pathlib
import re
import shutil
import subprocess
import sys
import time

PROFILES = {
    'system': [
        ('device_properties', ['shell', 'getprop']),
        ('kernel', ['shell', 'uname', '-a']),
        ('uptime', ['shell', 'uptime']),
        ('users', ['shell', 'pm', 'list', 'users']),
        ('storage', ['shell', 'df', '-h']),
        ('memory', ['shell', 'cat', '/proc/meminfo']),
        ('cpu', ['shell', 'cat', '/proc/cpuinfo']),
        ('mounts', ['shell', 'mount']),
        ('security_enforcing', ['shell', 'getenforce']),
        ('verified_boot', ['shell', 'getprop', 'ro.boot.verifiedbootstate']),
        ('security_patch', ['shell', 'getprop', 'ro.build.version.security_patch']),
    ],
    'apps': [
        ('packages_all', ['shell', 'pm', 'list', 'packages', '-f', '-i']),
        ('packages_third_party', ['shell', 'pm', 'list', 'packages', '-3']),
        ('packages_disabled', ['shell', 'pm', 'list', 'packages', '-d']),
        ('packages_system', ['shell', 'pm', 'list', 'packages', '-s']),
        ('appops', ['shell', 'cmd', 'appops', 'get', '--user', '0']),
        ('device_admin', ['shell', 'dumpsys', 'device_policy']),
        ('accessibility', ['shell', 'settings', 'get', 'secure', 'enabled_accessibility_services']),
        ('notification_listeners', ['shell', 'settings', 'get', 'secure', 'enabled_notification_listeners']),
        ('input_methods', ['shell', 'settings', 'get', 'secure', 'default_input_method']),
    ],
    'processes': [
        ('process_list', ['shell', 'ps', '-A']),
        ('top_snapshot', ['shell', 'top', '-b', '-n', '1']),
        ('meminfo', ['shell', 'dumpsys', 'meminfo']),
        ('activity_processes', ['shell', 'dumpsys', 'activity', 'processes']),
    ],
    'network': [
        ('interfaces', ['shell', 'ip', 'addr']),
        ('routes', ['shell', 'ip', 'route']),
        ('ipv6_routes', ['shell', 'ip', '-6', 'route']),
        ('sockets', ['shell', 'ss', '-tuna']),
        ('connectivity', ['shell', 'dumpsys', 'connectivity']),
        ('wifi', ['shell', 'dumpsys', 'wifi']),
        ('netstats', ['shell', 'dumpsys', 'netstats']),
        ('private_dns_mode', ['shell', 'settings', 'get', 'global', 'private_dns_mode']),
        ('private_dns_specifier', ['shell', 'settings', 'get', 'global', 'private_dns_specifier']),
    ],
    'battery': [
        ('battery', ['shell', 'dumpsys', 'battery']),
        ('batterystats', ['shell', 'dumpsys', 'batterystats', '--charged']),
        ('power', ['shell', 'dumpsys', 'power']),
        ('thermal', ['shell', 'dumpsys', 'thermalservice']),
    ],
    'security': [
        ('device_policy', ['shell', 'dumpsys', 'device_policy']),
        ('package_verifier', ['shell', 'settings', 'get', 'global', 'package_verifier_enable']),
        ('adb_enabled', ['shell', 'settings', 'get', 'global', 'adb_enabled']),
        ('development_settings', ['shell', 'settings', 'get', 'global', 'development_settings_enabled']),
        ('install_non_market_apps', ['shell', 'settings', 'get', 'secure', 'install_non_market_apps']),
        ('accessibility', ['shell', 'settings', 'get', 'secure', 'enabled_accessibility_services']),
        ('notification_listeners', ['shell', 'settings', 'get', 'secure', 'enabled_notification_listeners']),
        ('vpn', ['shell', 'dumpsys', 'vpn_management']),
    ],
    'logs': [
        ('logcat_recent', ['logcat', '-d', '-t', '2000', '-v', 'threadtime']),
    ],
}


def run(cmd, timeout):
    start = time.monotonic()
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, check=False)
        return {'exit_code': p.returncode, 'seconds': round(time.monotonic() - start, 2),
                'stdout': p.stdout.decode('utf-8', 'replace'),
                'stderr': p.stderr.decode('utf-8', 'replace')}
    except subprocess.TimeoutExpired as ex:
        return {'exit_code': None, 'seconds': round(time.monotonic() - start, 2),
                'stdout': (ex.stdout or b'').decode('utf-8', 'replace'),
                'stderr': 'TIMEOUT: ' + (ex.stderr or b'').decode('utf-8', 'replace')}
    except OSError as ex:
        return {'exit_code': None, 'seconds': round(time.monotonic() - start, 2),
                'stdout': '', 'stderr': str(ex)}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('profiles', nargs='*', choices=list(PROFILES) + ['all'],
                    metavar='PROFILE', help='system apps processes network battery security logs all')
    ap.add_argument('-s', '--serial', help='ADB serial, needed when several devices are connected')
    ap.add_argument('-o', '--output', default='reports', help='parent output directory')
    ap.add_argument('--timeout', type=int, default=35, help='seconds per command (default 35)')
    ap.add_argument('--package', help='also inspect one package name using dumpsys package and appops')
    args = ap.parse_args()
    if not shutil.which('adb'):
        ap.error('adb not found: install Android platform-tools')
    if args.timeout < 1:
        ap.error('--timeout must be positive')
    base = ['adb'] + (['-s', args.serial] if args.serial else [])
    state = run(base + ['get-state'], 10)
    if state['exit_code'] or state['stdout'].strip() != 'device':
        print('ADB device not ready. Check `adb devices -l` and authorize USB debugging.', file=sys.stderr)
        print(state['stderr'] or state['stdout'], file=sys.stderr)
        return 2
    serial = run(base + ['get-serialno'], 10)['stdout'].strip()
    safe_serial = re.sub(r'[^a-zA-Z0-9._-]', '_', serial)[:80]
    stamp = dt.datetime.now().astimezone().strftime('%Y%m%d_%H%M%S%z')
    out = pathlib.Path(args.output) / f'{stamp}_{safe_serial}'
    out.mkdir(parents=True, exist_ok=False)
    profiles = args.profiles or ['system', 'apps', 'processes', 'network', 'battery', 'security']
    if 'all' in profiles:
        profiles = list(PROFILES)
    profiles = list(dict.fromkeys(profiles))
    jobs = [(p, name, argv) for p in profiles for name, argv in PROFILES[p]]
    if args.package:
        if not re.fullmatch(r'[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+', args.package):
            ap.error('invalid package name')
        jobs += [('package', 'package_details', ['shell', 'dumpsys', 'package', args.package]),
                 ('package', 'package_appops', ['shell', 'cmd', 'appops', 'get', args.package])]
    manifest = {'timestamp': stamp, 'serial': serial, 'profiles': profiles, 'commands': []}
    for p, name, argv in jobs:
        folder = out / p
        folder.mkdir(exist_ok=True)
        print(f'[{p}] {name}', flush=True)
        result = run(base + argv, args.timeout)
        (folder / f'{name}.txt').write_text(result['stdout'], encoding='utf-8')
        if result['stderr']:
            (folder / f'{name}.stderr.txt').write_text(result['stderr'], encoding='utf-8')
        manifest['commands'].append({'profile': p, 'name': name, 'argv': argv,
                                     'exit_code': result['exit_code'], 'seconds': result['seconds'],
                                     'bytes': len(result['stdout'].encode('utf-8')),
                                     'error': result['stderr'][:500]})
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    failures = sum(c['exit_code'] != 0 for c in manifest['commands'])
    print(f'\nReport: {out}\nCommands: {len(jobs)}, failed/unavailable: {failures}')
    print('WARNING: Report may contain personal/device/network information. Do not publish unredacted.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
