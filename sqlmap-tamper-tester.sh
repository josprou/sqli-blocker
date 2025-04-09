#!/bin/bash

TARGET="$1"
TAMPER_DIR="/usr/share/sqlmap/tamper"
RESULTS_DIR="tamper_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo "[*] Probando cada tamper individual en: $TARGET"
echo "[*] Resultados en: $RESULTS_DIR"
echo

for tamper in "$TAMPER_DIR"/*.py; do
    name=$(basename "$tamper")
    echo "[+] Probando --tamper=$name"
    sqlmap -r "$TARGET" --tamper="$name" --batch --level=5 --risk=3 --flush-session \
      > "$RESULTS_DIR/$name.log" 2>&1
done

echo
echo "[✔] Pruebas completas. Revisa los logs en: $RESULTS_DIR"
