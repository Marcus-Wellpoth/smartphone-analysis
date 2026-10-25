import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from audit_report import analyze, render_html
from adb_inspector import PROFILES, command_status

class AuditTests(unittest.TestCase):
    def test_appops_requires_a_package(self):
        self.assertFalse(any(name == 'appops' for name, _ in PROFILES['apps']))

    def test_command_status(self):
        self.assertEqual(command_status({'exit_code': 0, 'stdout': 'tcp LISTEN',
                                         'stderr': 'Cannot open netlink socket: Permission denied'}), 'PARTIAL')
        self.assertEqual(command_status({'exit_code': 0, 'stdout': '',
                                         'stderr': 'Permission denied'}), 'FAILED')
        self.assertEqual(command_status({'exit_code': 255, 'stdout': '',
                                         'stderr': 'Error: Package name not specified'}), 'FAILED')
        self.assertEqual(command_status({'exit_code': 0, 'stdout': 'ok', 'stderr': ''}), 'SUCCESS')

    def test_old_manifest_detects_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'manifest.json').write_text(json.dumps({'commands': [
                {'profile': 'network', 'name': 'sockets', 'exit_code': 0,
                 'error': 'Cannot open netlink socket: Permission denied'},
                {'profile': 'apps', 'name': 'appops', 'exit_code': 255,
                 'error': 'Package name not specified'}
            ]}))
            result = analyze(root)
            self.assertEqual(result['partial_commands'], ['network/sockets'])
            self.assertEqual(result['failed_commands'], ['apps/appops'])
            self.assertIn('Teilweise auswertbare', render_html(result))

    def test_findings_and_stale_listener(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'manifest.json').write_text(json.dumps({'timestamp':'20261025', 'commands': []}))
            for name, value in {
                'system/security_patch.txt': '2025-09-01',
                'system/security_enforcing.txt': 'Enforcing',
                'system/verified_boot.txt': 'green',
                'system/bootloader_state.txt': 'locked',
                'security/notification_listeners.txt': 'com.deleted.app/.Listener:com.good.app/.Listener',
                'apps/packages_user.txt': 'package:com.good.app\n',
                'apps/packages_third_party.txt': 'package:com.good.app  installer=com.android.vending\n',
            }.items():
                f = root / name
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(value)
            report = analyze(root, dt.date(2026, 10, 25))
            ids = [f['id'] for f in report['findings']]
            self.assertIn('PATCH_OVER_YEAR', ids)
            self.assertIn('NOTIFICATION_LISTENERS', ids)
            self.assertIn('NOTIFICATION_LISTENERS_STALE', ids)
            self.assertNotIn('SELINUX_NOT_ENFORCING', ids)
            self.assertIn('Android Security Audit', render_html(report))

if __name__ == '__main__':
    unittest.main()
