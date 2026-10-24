#!/usr/bin/env python3
"""Test whether local WSL Python trusts the forged emSign chain.
VULNERABLE = accepted = certifi contains emSign ECC Root CA - G3.
PROTECTED  = SSLError = certifi patched.
"""
import re, socket, ssl, sys
import certifi
from cryptography import x509

HOST, IP, PORT = "test.example.com", "127.0.0.1", 8443

print("=" * 68)
print(f" certifi {certifi.__version__}")
print(f" bundle  {certifi.where()}")
print("=" * 68)

# Check whether certifi still carries the trust anchor
data = open(certifi.where(), "rb").read()
pems = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.S)
has_anchor = False
for p in pems:
    try:
        c = x509.load_pem_x509_certificate(p)
        if "emSign ECC Root CA - G3" in c.subject.rfc4514_string():
            has_anchor = True
            break
    except Exception:
        continue

if has_anchor:
    print("[*] emSign ECC Root CA - G3 IS in certifi bundle (pre-fix)")
else:
    print("[*] emSign ECC Root CA - G3 NOT in certifi bundle (patched)")
print()

def test_with(label, ctx):
    try:
        with socket.create_connection((IP, PORT), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=HOST) as s:
                print(f"  [{label}] VULNERABLE — accepted {s.version()} {s.cipher()[0]}")
                s.sendall(f"GET / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n".encode())
                resp = s.recv(2048).decode(errors="replace")
                print(f"           response: {resp.splitlines()[0]}")
                return True
    except ssl.SSLCertVerificationError as e:
        print(f"  [{label}] PROTECTED — {e.verify_message}")
        return False
    except ConnectionRefusedError:
        print(f"  [{label}] ERROR — server not running at {IP}:{PORT}")
        print(f"           start it first:  python3 app.py")
        sys.exit(2)

print("Test 1: certifi-only store (what `pip` uses by default)")
certifi_result = test_with("certifi", ssl.create_default_context(cafile=certifi.where()))
print()

print("Test 2: system store (Debian ca-certificates)")
system_result = test_with("system", ssl.create_default_context())
print()

print("=" * 68)
if certifi_result or system_result:
    print(" RESULT: VULNERABLE — a forged cert from the compromised CA was")
    print("         accepted. Any tool that uses this trust store is exposed.")
else:
    print(" RESULT: PROTECTED — both stores reject the forged cert.")
    print("         Fix is applied. This is the expected patched state.")
print("=" * 68)

sys.exit(0 if (certifi_result or system_result) else 1)
