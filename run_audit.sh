#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ ${1:-} == '--help' ]]; then
  echo 'Aufruf: ./run_audit.sh [ADB-SERIAL]'; exit 0
fi
command -v adb >/dev/null || { echo 'adb fehlt (sudo pacman -S android-tools)' >&2; exit 2; }
command -v python3 >/dev/null || { echo 'python3 fehlt' >&2; exit 2; }
if [[ $# -gt 1 ]]; then echo 'Maximal eine ADB-Seriennummer übergeben' >&2; exit 2; fi
SERIAL_ARGS=()
if [[ $# == 1 ]]; then
  SERIAL_ARGS=(-s "$1")
else
  mapfile -t DEVICES < <(adb devices | awk '$2=="device" {print $1}')
  if [[ ${#DEVICES[@]} -ne 1 ]]; then echo 'Genau ein autorisiertes Gerät anschließen oder Seriennummer angeben; adb devices -l' >&2; exit 2; fi
  SERIAL_ARGS=(-s "${DEVICES[0]}")
fi
printf '%s\n' 'Nur mit Einwilligung der Gerätebesitzerin/des Gerätebesitzers starten.'
read -r -p 'Einwilligung für read-only Diagnose und Speicherung lokaler Rohdaten liegt vor? [ja/NEIN] ' ANSWER
[[ "$ANSWER" == 'ja' ]] || { echo 'Abgebrochen.'; exit 1; }
mkdir -p reports
BEFORE=$(mktemp)
find reports -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort > "$BEFORE"
trap 'rm -f "$BEFORE"' EXIT
python3 adb_inspector.py system apps security processes network battery --audit-packages "${SERIAL_ARGS[@]}"
REPORT=$(comm -13 "$BEFORE" <(find reports -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort) | tail -n 1)
if [[ -z $REPORT ]]; then echo 'Kein neuer Report gefunden' >&2; exit 1; fi
python3 audit_report.py "reports/$REPORT"
printf '\nFertig: reports/%s/security_report.html\n' "$REPORT"
printf 'Rohdaten vertraulich behandeln; weder in Git einchecken noch ungeschwärzt weitergeben.\n'
