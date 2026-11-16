#!/usr/bin/env bash
set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1
python3 ss_sentinel.py
rc=$?
echo ""
echo "Tarama tamamlandi (cikis kodu: $rc). Raporlar reports/ klasorune kaydedildi."
read -r -p "Kapatmak icin Enter tusuna basin..."
exit "$rc"
