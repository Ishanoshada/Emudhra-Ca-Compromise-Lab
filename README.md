# eMudhra / emSign CA compromise (Oct 2026) — reproduction lab

A local, self-contained reproduction of the **eMudhra/emSign intermediate
CA compromise** disclosed in October 2026, plus a differential test across
six client trust configurations on the same machine.

A single leaf certificate signed with a recovered compromised key is served
over TLS. Six clients with six different trust stores connect to it. Two
accept it, four reject it. The forged cert is identical for every client;
only each client's trust configuration differs. That is the entire finding.

**For authorized security testing only.** Test clients you own or have
written permission to test. Do not use to intercept third-party traffic.

---

## Contents

- [TL;DR](#tldr)
- [The incident](#the-incident)
- [Patched versions](#patched-versions)
- [What this repository demonstrates](#what-this-repository-demonstrates)
- [Repository layout](#repository-layout)
- [Quick start](#quick-start)
- [Observed results](#observed-results)
- [Deep analysis per client](#deep-analysis-per-client)
- [Hidden trust stores](#hidden-trust-stores)
- [What this repository does *not* do](#what-this-repository-does-not-do)
- [Cleanup](#cleanup)
- [References](#references)

---

## TL;DR

Eight eMudhra (emSign) intermediate CAs were created in April 2025 with
P-384 keys whose private scalar `d` was a single small integer
(`d ∈ {4, 56, 66, 115, 155, 156, 230, 237}`). Anyone can recover the
private key from the public certificate in milliseconds. Six could mint
TLS certificates for any hostname; two were code-signing CAs.

Browsers blocked the eight keys via OneCRL / CRLSet / Apple / Windows
update between 17 and 22 October 2026. Patched releases of Go, Node,
Python `certifi`, `pip`, and OS CA bundles followed. **Browsers are
protected. Most non-browser software is not, unless its trust store was
updated to remove the roots or block the keys.** Any client that uses
its own bundled trust store, or that does not enforce revocation, will
accept a forged certificate until it is updated.

This lab issues a certificate forged with the recovered private key for
`EM DV TLS CA - G3B` (`d = 156`) and proves, on one machine, that:

- An **unpatched** trust store accepts the forged cert (`200 OK`).
- A **patched** client rejects it, each via its own mechanism
  (`CERT_REVOKED`, `CRYPT_E_REVOKED`, interstitial, `unknown authority`).

Nothing in the server can influence which verdict a client reaches.
Trust is a client-side decision.

---

## The incident

| Date | Event |
|---|---|
| 30 Apr 2025 | Eight intermediates created in a ceremony. A bug in the key-generation script produces a second, weak key set on the HSM; the weak keys end up in the CSRs. |
| May 2025 | All eight are cross-signed by Sectigo's legacy **AAA Certificate Services** root. |
| 17 Oct 2026 | Researcher "Wayne" reports the weakness. Chrome (CRLSet) and Firefox (OneCRL) block the keys within hours. |
| 19 Oct 2026 | Apple blocks via macOS/iOS update. Android via Play Services. |
| 20 Oct 2026 | Microsoft blocks via Windows Update. Go releases 1.27.3 / 1.26.10 (CVE-2026-111943). BleepingComputer publishes. |
| 22 Oct 2026 | Apple protections reach full rollout (per coverage). |

Because no TLS certificate chaining to the six TLS intermediates was
ever logged to Certificate Transparency during the ~17-month exposure
window, CT-enforcing browsers were protected throughout.

### Affected trust anchors

| Root | Role |
|---|---|
| `emSign ECC Root CA - G3` | The trust anchor. Removed from Mozilla NSS 3.131.1. |
| `emSign Root TLS CA - G3` | Direct issuer of the TLS intermediates. |
| `emSign Root CS CA - G3` | Code-signing anchor, trusted by Windows. |
| `AAA Certificate Services` | Sectigo / legacy Comodo cross-signer. **Still trusted for TLS on Debian/Ubuntu and in Java `cacerts`.** |

**The critical nuance:** removing the emSign roots is not sufficient
for clients that still trust `AAA Certificate Services` for TLS. The
Sectigo cross-signed copies of the compromised intermediates verify
against AAA. Those clients need a **key-based (SPKI) block** or
revocation enforcement, not just root removal.

This is why Go 1.27.3 / Node 24.22.1 / Windows Schannel ship a
compiled-in **SPKI blocklist** rather than relying only on a root
store update.

## Patched versions

From the incident gist and BleepingComputer coverage (20 Oct 2026):

| Software | Patched version / status |
|---|---|
| Ubuntu `ca-certificates` | `20260816ubuntu0.{22.04,24.04,26.04,26.10}.1` |
| Ubuntu 14.04–20.04 | via Ubuntu Pro / ESM (see USN-8944-1) |
| Debian `ca-certificates` | `20250419~deb12u2` / `+deb13u1` / `20260816+nmu1` |
| Arch `ca-certificates-mozilla` | `3.131.1-1` |
| Gentoo `ca-certificates` | `20260816.3.125` |
| Chainguard `ca-certificates` | `20260909-r3` |
| Alpine `ca-certificates` | `20261020-r0` |
| FreeBSD `ca_root_nss` | Pending at time of writing |
| NSS | `3.131.1` |
| curl CA bundle | `2026-10-20` |
| Homebrew `ca-certificates` | `2026-09-25_1` |
| **Go** | **`1.27.3`, `1.26.10`** (CVE-2026-111943) |
| **Node.js** | **`v26.12.1`, `v24.22.1`, `v22.23.4`** |
| Python `certifi` | `2026.10.19` |
| `pip` | `26.2.2` (with `UV_SYSTEM_CERTS=true` for uv: `0.13.4`) |
| `sigstore` | `4.5.1` |
| `pixi` | `0.82.1` |
| Rust `rustls-webpki` | `0.103.16` |
| Rust `webpki-roots` / `webpki-root-certs` | `1.0.10` |
| Electron | `44.9.1`, `43.8.1`, `42.11.16` |
| Composer `ca-bundle` | `1.4.16`, `1.6.0` |
| Elixir `castore` | `1.0.22` |
| Perl `Mozilla::CA` | `20261020` |
| Bun | Pending at time of writing |

---

## What this repository demonstrates

A forged leaf certificate signed with the recovered key of
`EM DV TLS CA - G3B` (`d = 156`) is served by a Flask HTTPS server. Six
clients connect to the same server, same forged cert, same chain:

| Client | Trust source | Result |
|---|---|---|
| WSL Python 3.13 (`certifi 2026.06.17`) | `certifi` bundle (still carries the emSign root) | **VULNERABLE** |
| WSL Python 3.13 (system store) | Debian `ca-certificates` (unpatched) | **VULNERABLE** |
| PHP 8.5.10 `openssl` + `old-cacert.pem` | old certifi bundle | **VULNERABLE** |
| Go 1.27.1 + `RootCAs = old-cacert.pem` | custom pool containing the emSign root | **VULNERABLE** (CVE-2026-111943) |
| Node 24.22.1 (patched) | compiled SPKI blocklist + NSS 3.131.1 | **PROTECTED** (`CERT_REVOKED`) |
| Windows curl (Schannel) | Windows store + disallowed-cert CTL | **PROTECTED** (`CRYPT_E_REVOKED`) |
| Firefox | NSS 3.131.1 + OneCRL + CT | **PROTECTED** (interstitial) |
| PHP 8.5.10 `curl` (no cafile) | none | "safe by accident" (see notes) |
| Go 1.27.1 default system roots | Go bundled roots (no emSign root) | "accidental protection" (see notes) |

Two of the "protected" rows are accidental — the client happened to
have nothing to trust. Those rows would flip to **VULNERABLE** on a
deployment that supplies the emSign root via a custom bundle, as rows
3 and 4 show. Do not cite them as evidence the fix is applied.

---

## Repository layout

```
lab/
├── README.md                 this file
├── app.py                    Flask HTTPS server (runs in WSL)
├── fetch_chain.sh            fetches chain-1.pem / chain-2.pem from the
│                             disclosure test host, or reuses local copies
├── intermediate.pem          EM DV TLS CA - G3B  (the compromised intermediate)
├── chain2.pem                emSign Root TLS CA - G3  (upper intermediate)
├── chain.pem                 GENERATED by app.py on each run
├── leaf.key                  GENERATED by app.py on each run
├── old-cacert.pem            certifi 2026.06.17 bundle (test fixture)
└── poc/
    ├── go.mod
    ├── test_vulnerable.py    WSL: certifi + system store
    ├── test-node.js          Windows: Node bundled roots
    ├── test-php.php          Windows: PHP curl + PHP openssl
    └── test-go.go            Windows: Go default + custom RootCAs
```

`intermediate.pem` and `chain2.pem` are the **real public certificates**
of the compromised chain, fetched from the disclosure test host. `d=156`
is the published private scalar for `EM DV TLS CA - G3B`; `app.py`
derives it with `ec.derive_private_key(156, SECP384R1())` at startup and
signs the forged leaf with it. The `[+] matched d=156` line in the
startup banner confirms the intermediate matches one of the eight
published weak keys.

---

## Quick start

### Prerequisites

- **WSL** (Debian or Ubuntu) with Python 3.11+ and `flask` + `cryptography`:
  ```bash
  python3 -m pip install --user flask cryptography
  ```
- **Windows** with Node, PHP (curl + openssl extensions), Go, and curl in PATH.
- The old certifi bundle on disk as `old-cacert.pem`. To regenerate:
  ```bash
  python3 -m venv /tmp/oldcert && . /tmp/oldcert/bin/activate
  pip install 'certifi==2026.06.17'
  cp "$(python3 -c 'import certifi; print(certifi.where())')" old-cacert.pem
  ```

### Start the server (WSL, terminal 1)

```bash
cd /mnt/d/github/bug/emudra/lab
./fetch_chain.sh            # only needed if intermediate.pem/chain2.pem missing
python3 app.py
```

Startup:

```
====================================================================
 eMudhra/emSign forged-cert server — FOR AUTHORIZED TESTING ONLY
====================================================================
 intermediate : CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL
 SPKI         : EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105
 recovered d  : 156
 chain2       : CN=emSign Root TLS CA - G3,O=eMudhra Technologies Limited,C=IN
 wrote        : chain.pem, leaf.key
[+] listening on https://0.0.0.0:8443/
```

### Confirm Windows can reach it (Windows cmd)

```cmd
curl -k https://localhost:8443/
```

`OK GET /` means WSL2 localhost forwarding works. If not, get the WSL IP
with `hostname -I | awk '{print $1}'` and replace `127.0.0.1` in each
test script with that address.

### Run the tests

WSL (terminal 2):

```bash
cd /mnt/d/github/bug/emudra/lab/poc
python3 test_vulnerable.py
```

Windows cmd:

```cmd
cd D:\github\bug\emudra\lab\poc
node test-node.js
php  test-php.php
go   run test-go.go
```

`test-php.php` and `test-go.go` reference `../old-cacert.pem`, so run
them from `poc/`. Each script prints a `RESULT:` line ending in
`VULNERABLE` or `PROTECTED`.

---

## Observed results

Reproduced on this machine, 24 Oct 2026:

### Vulnerable — forged cert accepted

```
WSL Python 3.13, certifi 2026.06.17     accepted TLSv1.3  →  HTTP 200
WSL Python 3.13, Debian system store    accepted TLSv1.3  →  HTTP 200
PHP 8.5.10 openssl + old-cacert.pem     handshake OK
Go 1.27.1 RootCAs = old-cacert.pem      HTTP/1.1 200 OK    (CVE-2026-111943)
```

### Protected — forged cert rejected

```
Node 24.22.1                            CERT_REVOKED  (SPKI blocklist fired)
Windows curl (Schannel)                 CRYPT_E_REVOKED  (disallowed CTL)
Firefox                                 interstitial (NSS root removal + OneCRL + CT)
```

### Accidental protection — do not cite as a fix

```
PHP 8.5.10 curl, no cafile              errno 60  (nothing to trust)
Go 1.27.1 default system roots          unknown authority  (root not bundled)
```

Both of these would become VULNERABLE if the emSign root were
present in a custom bundle — see the first table above.

---

## Deep analysis per client

### Python — `test_vulnerable.py`

Two tests: one with `cafile=certifi.where()`, one with the OS store.
Both accept the forged cert because `certifi 2026.06.17` still contains
`emSign ECC Root CA - G3`, and Debian's system `ca-certificates` in
WSL has not been updated.

This is the finding the disclosure calls out for `pip < 26.2.2`: pip
loads its **own** vendored `certifi` on top of the system store with no
opt-out, so OS-level distrust does not protect pip. A project whose
lockfile pulls in an old `certifi` is exposed regardless of the host's
package state.

Fix: upgrade `certifi` to `2026.10.19` or newer, and upgrade `pip` to
`26.2.2` or newer.

### PHP — `test-php.php`

Four rows:

1. **`curl` (no cafile)** — rejected, but only because
   `openssl.cafile` and `curl.cainfo` are unset in this PHP install, so
   curl has nothing to trust. This is accidental. A real deployment
   with `curl.cainfo = old-bundle.pem` would accept the forged cert,
   same shape as row 3.
2. **`curl` (no-revoke)** — identical, because WinLibs PHP uses OpenSSL,
   not Schannel. The Windows disallowed CTL is not in play here at all.
3. **`openssl` + `old-cacert.pem`** — **VULNERABLE**, handshake OK.
   Any PHP application with `openssl.cafile` pointing at an old bundle
   accepts the forged cert. This is the real exposure.
4. **`openssl` with no cafile set** — `NO-CA`, meaning no CA was loaded
   at all. Not a security result.

Fix: update the CA bundle. Composer's own `ca-bundle` is patched in
`1.4.16` / `1.6.0`; that only covers Composer, not PHP itself.

### Go — `test-go.go`

| Row | Result | Interpretation |
|---|---|---|
| `[default]` (system roots) | `unknown authority` | **Accidental protection.** Go 1.27.1's bundled roots don't include `emSign ECC Root CA - G3`. On hosts where the root *is* present — macOS with the AAA cross-sign, older Debian/Ubuntu before the fix — the default path would accept the forged cert. |
| `[old-cacert]` (`RootCAs` = old bundle) | `HTTP 200` | **The CVE-relevant result.** With `RootCAs` supplying the emSign root, Go 1.27.1 has no SPKI blocklist and accepts the forged chain. This is CVE-2026-111943. |
| `[insecure]` (`InsecureSkipVerify`) | `HTTP 200` | Control — proves the network path and the forged cert both work. |

The fix (Go **1.27.3** / **1.26.10**) is a compiled-in SHA-256 SPKI
blocklist enforced on **all verification paths, including
Darwin/Windows system verify**. After upgrading, the `[old-cacert]` row
flips to PROTECTED — the blocklist fires even though the root is present
in the custom pool. That is the whole point of the CVE.

Rebuild every Go binary and container with the new toolchain. Old
binaries with a stale embedded trust store remain exposed.

### Node — `test-node.js`

```
[default]    PROTECTED — CERT_REVOKED: certificate revoked
[unverified] VULNERABLE — HTTP 200 from forged cert
```

Node 24.22.1 ships both parts of the fix:

1. **Compiled-in SPKI blocklist** — byte-identical to Go's — reports
   `CERT_REVOKED`.
2. **Root store update to NSS 3.131.1** — would have reported
   `UNABLE_TO_GET_ISSUER_CERT` / `SELF_SIGNED_CERT_IN_CHAIN`.

`CERT_REVOKED` means the SPKI blocklist fired, not the root removal.
That is the stronger of the two defenses: it works even if an admin
re-adds the emSign root to a custom pool. The `[unverified]` row is the
control — it proves the forged cert is genuinely being served and that
the rejection is a trust decision, not a network failure.

Fixed: **v26.12.1, v24.22.1, v22.23.4**. Sessions resumed before the
upgrade are not re-verified until they time out — restart long-lived
Node processes after upgrading.

### Firefox

Three independent client-side layers reject the forged chain:

1. **NSS 3.131.1 root removal** — `emSign ECC Root CA - G3` is gone.
2. **OneCRL SPKI block** — the eight compromised intermediates are
   revoked by public key, not serial.
3. **Certificate Transparency** — the forged leaf has no valid SCTs,
   and no CT log will sign one for a key that is already blocked.

Any one is fatal. All three are active. There is **no server-side
change and no certificate regeneration** that will make a patched
Firefox accept the forged cert silently. The interstitial is the
correct result and belongs in the matrix as **PROTECTED**.

The only way to see "Firefox accept" is to disable the fix in a
throwaway profile (import `emSign ECC Root CA - G3` into Authorities,
set `security.pki.certificate_transparency.mode = 0` and
`security.remote_settings.crlite_filters.enabled = false`). If you do,
label the result **simulated pre-Oct-2026 Firefox**, not "bypass." You
removed the fix; you did not defeat it.

### Windows curl (Schannel)

```
schannel: trust for this certificate or one of the certificates in the
certificate chain has been revoked
curl: (60)
```

The rejection comes from the **disallowed-certificate CTL**, a
kernel-enforced blocklist pushed via Windows Update. `--cacert
old-cacert.pem` does **not** override it — the CTL is applied at a
layer below the CA bundle. `--ssl-no-revoke` disables Schannel's
revocation check but **not** the CTL; the result is the same error.

Per the disclosure: *"Windows CryptoAPI only rejects the chains when
revocation checking is switched on."* The CTL is the reason.

---



### `pip` specifically

`pip < 26.2.2` always loads its vendored `certifi` on top of the system
store with no way to turn that off, so OS-level distrust does not
protect `pip`. Only upgrading `pip` works. Bootstrap a secure `pip`
first, then upgrade everything else:

```bash
python -m pip install \
  "pip @ https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
python -m pip install --upgrade certifi uv
UV_SYSTEM_CERTS=true uv self update
```

macOS python.org installers bundle `certifi`, so update it there too.
Until CPython security releases fix the bundled `pip` (GH-159910),
upgrade `pip` after every fresh venv.

### Java — the hard case

Java uses a static `cacerts` per JDK, has no CT enforcement, and has
revocation checking off by default (`com.sun.net.ssl.checkRevocation=false`).
Outbound HTTPS from `HttpClient`, Spring, OkHttp, Netty etc. with
default settings accepts the forged chain. Test any JDK with
Mark Struberg's `CheckCompromisedCa.java` against the 12
`*-emudhra.we-have-a-problem.com` test hosts.

The trap: `cacerts` also contains `AAA Certificate Services`
(`comodoaaaca`). Deleting the emSign roots is not enough — the
cross-signed chains still verify. Deleting `comodoaaaca` too blocks
them but breaks legitimate legacy Sectigo chains.

**Proper fix:** append the **16 certificate SHA-256 hashes**
(8 keys × 2 issuers) to `$JAVA_HOME/lib/security/blocked.certs`. The
JVM checks this list during every chain validation ("Untrusted
certificate") with no collateral damage. The full hash list is in
Laforge's post (see References). Do this for every JDK
(`~/.sdkman/candidates/java/*/`), then re-run `CheckCompromisedCa.java`
to confirm all 12 connections are rejected.

GraalVM native images embed the trust config at build time — patch the
host JDK, then rebuild the binary. Container images freeze
`cacerts` / `blocked.certs` at build time — add a `RUN` step appending
the 16 hashes, or wait for an updated base image.

---

## Hidden trust stores

Some libraries ship their own frozen PEM instead of a bundle package
(Python HTTP clients as fallback, Ruby gems with 11-year-old lists).
Scan any bundle for the affected root fingerprints:

```
AAA Certificate Services  D7A7A0FB 5D7E2731 D771E948 4EBCDEF7 1D5F0C3E 0A294878 2BC83EE0 EA699EF4
emSign ECC Root CA - G3   86A1ECBA 089C4A8D 3BBE2734 C612BA34 1D813E04 3CF9E8A8 62CD5C57 A36BBE6B
emSign Root TLS CA - G3   7DD78D5F 4F13459A 83DFF9AB BBA62EDB AF6F2D10 2BF257FD 712F4D9F 2746ED8D
emSign Root CS CA - G3    F2EDAAFF 3D9B701F B4D14C9F 285F8C0B AD90FC3B CC1FA07D 47F4718E DABA34A5
```

One-liner:

```bash
AFFECTED='D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4
86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D
F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5'
awk '/BEGIN CERT/{n++} n{print > ("c" n ".pem")}' bundle.pem
for c in c*.pem; do
  fp=$(openssl x509 -in "$c" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':')
  grep -qx "$fp" <<<"$AFFECTED" && echo "AFFECTED $c"
done
```

Run against every `cacert.pem` in your environments — dev boxes, CI
runners, container base images, vendored bundles in language runtimes,
the built-in bundle inside a Go binary you haven't rebuilt, the
`ca-bundle` inside a Composer install.

---

## What this repository does *not* do

- **It does not bypass any client's protection.** Firefox warning,
  Windows `CRYPT_E_REVOKED`, Node `CERT_REVOKED` — all are the fix
  working. There is no `app.py` change, no cert shape, and no chain
  reordering that flips them.
- **It does not exploit a browser.** No memory corruption, no `firefox.exe`
  patch, no CT / OneCRL defeat. Those are browser-exploit techniques,
  not CA-compromise demonstrations, and they are not the point of this
  incident.
- **It does not prove any specific client is vulnerable on your
  deployment.** It proves *this machine's* trust configurations. The
  matrix on your infrastructure depends entirely on which CA bundles
  each runtime and each tool uses — check them with the scan script
  above.

---

## Cleanup

Stop the Flask server (`Ctrl+C` in WSL terminal 1).

Remove any hosts entry you added (`test.example.com` → `127.0.0.1` in
`/etc/hosts` or `C:\Windows\System32\drivers\etc\hosts`), then
`ipconfig /flushdns`.

`chain.pem` and `leaf.key` are regenerated on each `app.py` run and can
be deleted. `intermediate.pem`, `chain2.pem`, `old-cacert.pem`, and the
`poc/` scripts are the durable artifacts.

---

## References

- Disclosure site with signatures, chains, and test hosts:
  `https://emudhra.we-have-a-problem.com`
- Mozilla bug **2083449** — incident tracker / eMudhra root-cause account
- Mozilla `dev-security-policy` thread — OneCRL rollout, Chrome Root
  Program response
- **CVE-2026-111943** / `go/go#82345` — Go `crypto/x509` SPKI blocklist
- `nodejs/node#66871` — Node.js SPKI blocklist + NSS 3.131.1 root store
- **GHSA-6q48-6c7w-9gw2** — Python `certifi` advisory
- `discuss.python.org` — packaging thread (`pip` bundled `certifi`)
- G. Laforge, "Why Your JVM Is Vulnerable"
- Ubuntu **USN-8944-1** — `ca-certificates` fix
- Red Hat **RHSB-2026-012**