# ADB Inspector

Read-only diagnostic toolkit for an Android device you own or are authorized to inspect. Runs on Linux with Python 3 and `adb` (Android platform-tools), without Python dependencies and typically without root.

## Start

```bash
sudo pacman -S android-tools python
adb devices -l
python3 adb_inspector.py system apps security
```

Enable developer options / USB debugging on Android and accept the computer's RSA authorization prompt. For multiple devices supply `-s SERIAL` (find the serial with `adb devices -l`). Reports appear in `reports/<timestamp>_<serial>/`.

## Profiles

- `system`: build, patch level, memory, storage, boot/security info
- `apps`: installed/disabled/third-party packages, app operations, sensitive system app settings
- `processes`: process and memory snapshots
- `network`: local interfaces, routes, sockets, connectivity, DNS, Wi-Fi stats
- `battery`: battery, battery usage, power and thermal status
- `security`: device policy, debugging state, listeners, some VPN info
- `logs`: last 2,000 logcat entries; **explicit opt-in** as logs can contain sensitive information

```bash
python3 adb_inspector.py                       # default profiles, no logcat
python3 adb_inspector.py all                   # includes logcat
python3 adb_inspector.py apps --package com.example.app
python3 adb_inspector.py network battery -s SERIAL -o ~/phone-audits
python3 compare_reports.py OLD_REPORT NEW_REPORT
python3 compare_reports.py OLD_REPORT NEW_REPORT --all
```

## Interpretation and limitations

- No command attempts to install, delete, change settings, reset stats, grant permissions or gain root.
- Some commands fail or return partial information on particular Android/OEM versions because of permissions, removed shell utilities or changed service names. Failures are recorded in `manifest.json` and `.stderr.txt`.
- AppOps output alone does not establish that an app is malicious. `pm list packages -3` is not a perfect representation of every user-installed app.
- `ss` and process output may be access-restricted; `logcat` may exclude other apps' entries.
- Dumpsys output can disclose Wi-Fi details, app usage, account identifiers, IP addresses, etc. Treat reports as **confidential** and review/redact before sharing.
- Reports are snapshots, not complete forensic images. They cannot prove the absence of malware.
- For a single app, review `package/package_details.txt` for requested/install-time/runtime permissions and components, plus `package/package_appops.txt` for recorded operations.

Official reference: https://developer.android.com/tools/adb and https://developer.android.com/tools/dumpsys

## Field security audit (v0.2)

**Always obtain the device owner's consent.** This tooling uses read-only ADB operations. It **does not** install apps, change settings, remove packages, attempt rooting, or collect logcat by default. Use only on devices you're authorized to inspect. Reports contain personal data and must remain private.

```bash
chmod +x run_audit.sh
./run_audit.sh                  # one connected device; interactive consent confirmation
./run_audit.sh SERIAL           # select specific device
```

The script collects `system apps security processes network battery` plus per-third-party-package `dumpsys package` and `appops get` output. It writes `reports/<date>_<serial>/security_report.html` for a local browser and `security_findings.json` for automation. Per-package collection may take time; vendor-restricted commands are marked as failed. The report includes coverage gaps. No logcat is collected in the normal field workflow. **Do not commit or upload reports.**

Alternatively use the individual commands:

```bash
python3 adb_inspector.py system apps security --audit-packages
python3 audit_report.py reports/NAME_OF_LATEST_REPORT
python3 compare_reports.py reports/OLD reports/NEW
python3 -m unittest discover -s tests -v
```

Interpretation: `HIGH` means a prioritized concern, not proven compromise; `MEDIUM` a security weakness; `REVIEW` contextual/manual review; `INFO` informational. Installer attribution is not cryptographic verification. An old patch date cannot be fixed by an app audit. ADB does not reliably expose every app's traffic or forensic artifacts.
