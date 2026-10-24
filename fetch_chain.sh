#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if [ -f intermediate.pem ] && [ -f chain2.pem ]; then
    echo "[+] chain certs already present"
    exit 0
fi

# Try existing files first
if [ -f /mnt/d/github/bug/emudra/chain-1.pem ] && [ -f /mnt/d/github/bug/emudra/chain-2.pem ]; then
    cp /mnt/d/github/bug/emudra/chain-1.pem intermediate.pem
    cp /mnt/d/github/bug/emudra/chain-2.pem chain2.pem
    echo "[+] copied chain-1.pem, chain-2.pem from existing emudra folder"
    exit 0
fi

# Otherwise fetch from disclosure test host
echo "[+] fetching chain from dv-g3b-emudhra.we-have-a-problem.com"
openssl s_client -showcerts \
  -connect dv-g3b-emudhra.we-have-a-problem.com:443 \
  -servername dv-g3b-emudhra.we-have-a-problem.com \
  </dev/null > chain.txt 2>&1

python3 - <<'PY'
import re, sys
data = open("chain.txt", encoding="utf-8", errors="ignore").read()
certs = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.S)
if len(certs) < 2:
    sys.exit(f"[!] expected >=2 certs, got {len(certs)} — disclosure host unreachable?")
open("intermediate.pem", "w").write(certs[1] + "\n")
if len(certs) >= 3:
    open("chain2.pem", "w").write(certs[2] + "\n")
print(f"[+] wrote intermediate.pem, chain2.pem ({len(certs)} certs total)")
PY
