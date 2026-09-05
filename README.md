# Salat Stealer — Reverse-Engineering an Active Go-Based MaaS Infostealer

**Author:** eva420
**Classification:** TLP:CLEAR · IOCs safe to share
**Type:** Independent malware analysis / threat research

> Independent, end-to-end analysis of a trojanized "gamer tools" pack found in the
> wild. The pack dropped a `garble`-obfuscated **Go loader** that abused **GitHub
> Releases as a free CDN** (a living-off-trusted-services / LOTS technique) and
> carried a second, encrypted payload embedded in its own binary. I reverse-engineered
> the loader in Ghidra, extracted and decrypted the embedded payload, detonated it in
> an isolated lab to recover its live command-and-control (C2), and then mapped the
> wider infrastructure with passive OSINT. The payload is **Salat Stealer**, a Go
> infostealer/RAT sold as Malware-as-a-Service by Russian-speaking actors. The
> distribution binaries had **>170,000 combined downloads** — an active campaign at
> scale, not a one-off.

---

## Contents
1. [Key findings](#1-key-findings)
2. [Distribution vector](#2-distribution-vector)
3. [Stage 1 — the Go loader](#3-stage-1--the-go-loader)
4. [Stage 2 — extracting the embedded payload](#4-stage-2--extracting-the-embedded-payload)
5. [The payload — Salat Stealer](#5-the-payload--salat-stealer)
6. [C2 discovery — controlled detonation](#6-c2-discovery--controlled-detonation)
7. [Infrastructure mapping](#7-infrastructure-mapping-passive-osint)
8. [Attribution](#8-attribution)
9. [Indicators of Compromise (IOCs)](#9-indicators-of-compromise)
10. [Detection & mitigation](#10-detection--mitigation)
11. [Methodology, tooling & ethics](#11-methodology-tooling--ethics)

---

## 1. Key findings

- A "gamer tools" pack (fake Roblox executors, Nitro/Fortnite generators, cheat menus)
  is a **malware delivery vehicle**. One component, presented as a `.NET/WPF` app, is
  actually a **Go 1.25.3 binary** obfuscated with `garble`.
- The loader is **sandbox-aware** (it stayed silent under naïve dynamic analysis),
  performs a **UAC bypass**, and carries **two independent payload paths**:
  1. a **ChaCha20-Poly1305 + zstd** payload embedded inside the binary itself, and
  2. a **remote "update"** fetched from **GitHub Releases** — letting the operator swap
     the payload by uploading a new release, without ever touching the loader.
- The embedded payload decrypts to a **12.5 MB Go PE32** identified as **Salat Stealer**
  (browser credentials, crypto-wallet extensions, LSASS, Steam/Discord tokens, remote
  shell, persistence).
- The stealer uses **DNS-over-HTTPS** to hide C2 resolution and falls back to the
  **TON blockchain** for C2 discovery when its hardcoded domains die.
- Passive OSINT expanded a documented set of 5 C2 domains to **12 domains + a live admin
  panel**, including operator **OPSEC failures** (C2 panels registered through Cloudflare
  but *not* proxied, exposing their real origin at abuse-tolerant hosting).
- The distribution binaries recorded **>170,000 downloads** on GitHub before analysis.

---

## 2. Distribution vector

The sample set arrived as a large archive (~1.2 GB) of nine "gaming utilities" shared
through a public file-sharing link. Most items were password-protected decoys stuffed
with anti-sandbox filler (one bundled the source of the well-known `al-khaser` anti-analysis
project; another was inflated to ~790 MB purely to frustrate automated analysis).

The operationally interesting component was a single loader. Static triage of the pack
(hashing, string extraction, archive inspection) was done in an isolated Linux VM before
anything was executed.

> **Sanitization note.** Details that identify the original victim, the specific
> distribution accounts, and any named individuals have been deliberately removed from
> this public write-up. Personal attribution was documented separately and referred to
> law enforcement. What remains here is infrastructure- and technique-level intelligence,
> most of which is already public in vendor reporting.

---

## 3. Stage 1 — the Go loader

Presented as a `.NET/WPF` application, the loader is a real **Go 1.25.3** binary,
obfuscated with **`garble`** (function names and build paths stripped — deliberate OPSEC).
Reversing `main.main` in Ghidra revealed the following flow:

1. **`stealth.RunStealth(...)`** — virtualization/sandbox detection. This is why the
   binary produced *zero* network traffic during initial dynamic detonation inside a VM.
2. **`uac.RunDefaultUAC()`** — UAC bypass / elevation.
3. **Embedded payload execution** — decrypts (ChaCha20-Poly1305) and decompresses (zstd)
   a ~5 MB payload carried inside the binary, writes it to
   `%APPDATA%\<existing-random-folder>\agent_<8-random-chars>.exe`, and runs it hidden
   (`HideWindow = true`).
4. **Remote update path** — with a runtime condition, after a random 60–420 s delay, it
   issues an HTTP `GET` to a **GitHub Releases** asset (`service.exe`) and runs it with
   the same drop-and-run routine. This is the campaign's update/C2 mechanism: the payload
   can be rotated by publishing a new GitHub release.

**RE note worth its own paragraph.** The C2 string was *not* where Ghidra's decompiler
pointed. The decompiler resolved a pointer to `0x140aed480`, which turned out to be an
internal shared symbol of Go's `encoding/base64`. The real string lived at the pointer in
`0x140ade140` (length `0x140ade148`, len = 104) and had to be read from the **raw
disassembly** of `main.main`, not the pseudocode. Go data layout regularly defeats
decompiler heuristics; cross-checking against raw disassembly is essential.

**ChaCha20-Poly1305 key** (same key used for both the embedded payload and the chunked
blob in Stage 2):

```
f222227925253d5b827a363444728c667e3fdeff5a122556cd8935893154c1ba
```

---

## 4. Stage 2 — extracting the embedded payload

Beyond the GitHub update path, the loader embeds a full payload **inside its own binary**,
encrypted in chunks and wrapped in **CBOR**:

```
{ "c": [ 35 × ChaCha20-Poly1305 chunks ],
  "n": [ 35 × 12-byte nonces ] }
```

The pointer / length / capacity of the CBOR blob sit in the globals
`0x140adf7e0 / 0x140adf7e8 / 0x140adf7f0`, pointing to **5,115,479 bytes** at
`0x1405e4d20`.

Extraction and decryption:

1. Dump the mapped blob with a **Ghidra headless** script (reading memory Ghidra had
   already mapped, rather than trusting decompiler addresses).
2. Parse the CBOR (`cbor2`), decrypt the 35 chunks with the known key
   (`cryptography.ChaCha20Poly1305`), concatenate → **5,114,280 bytes** beginning with the
   **zstd magic** (`28 b5 2f fd`).
3. Decompress (`zstandard`) → **12,570,624 bytes**, a valid **PE32 (i386)**.

Decrypted payload:

```
SHA-256: c935e0e1f2a230b4583b8d46a607631f4f27d7b582e76a341f82d130805e0d17
```

The PE is GUI-subsystem and imports **only `KERNEL32.DLL`** — typical of a Go binary that
resolves everything else via direct syscalls.

---

## 5. The payload — Salat Stealer

Static analysis of the 12.5 MB payload (Go build info + strings) maps cleanly onto a
feature-rich stealer/RAT:

- **Browser theft** — passwords and cookies from Chrome/Chromium (literal SQL such as
  `SELECT origin_url, action_url, username_value, password_value ... FROM logins` and the
  cookies query), Firefox (NSS, `nssPrivate`), and Russian/alternative browsers (Sputnik,
  Elements).
- **Crypto-wallet theft** — an embedded list of hundreds of Chrome extension IDs
  (MetaMask, TonKeeper, SuiWallet, Electrum, Coinbase, and many more).
- **Windows credential theft** — attempts to locate and dump **LSASS**
  (`failed to find LSASS process`, `failed to impersonate SYSTEM`) — Mimikatz-style
  behaviour, not just a browser stealer.
- **Gaming targets** — `SteamPath` (consistent with the "gamer tools" lure), Discord/Steam
  tokens.
- **Persistence & C2 plumbing (Go dependencies):** `capnspacehook/taskmaster` (Scheduled
  Tasks), `go-ole` + `wmi` (host fingerprinting), `ncruces/go-sqlite3` (local staging DB),
  `gorilla/websocket`, `quic-go` (HTTP/3, QUIC), `tetratelabs/wazero` (embedded WASM
  runtime — a likely hot-loaded plugin system), `xssnick/tonutils-go` (TON blockchain).
- **Exfiltration marker string:** `LOG SENT!`.

**Evasion / resilience:**

- **DNS-over-HTTPS** for name resolution, with at least three resolvers hardcoded in the
  clear (`1.1.1.1/dns-query`, `cloudflare-dns.com/dns-query`, `dns.google/resolve`) — this
  keeps the C2 domain off traditional DNS monitoring.
- **TON blockchain fallback** for C2 discovery when the hardcoded domains fail (this
  clarified the role of the `tonutils-go` dependency: resilience, not just wallet parsing).

The C2 domain is **not** present in cleartext strings; it is built/decrypted at runtime,
so it was recovered dynamically (next section).

---

## 6. C2 discovery — controlled detonation

The isolated analysis network had no internet egress, so the DoH-based resolution could
not complete. A **second NIC** was attached to the analysis VM on a dedicated, isolated
NAT network (host LAN unreachable, internet egress only) purely to observe real traffic,
with packet capture running before execution.

On detonation, the payload **self-relocated** to
`%LOCALAPPDATA%\Temp\Staem.exe` (a deliberate typosquat of `Steam.exe`) and then:

1. TLS to `dns.google` (`8.8.8.8`) — a DoH query (encrypted).
2. A fresh TLS connection to Cloudflare IPs whose **ClientHello SNI** (which is *not*
   encrypted) revealed the C2 in the clear: **`salator[.]es`**.
3. Near-simultaneous TLS to `github.com` and `raw.githubusercontent.com` — a likely
   module/plugin delivery channel (consistent with the embedded WASM runtime).

Extraction command (run inside the VM):

```bash
tshark -r capture.pcapng \
  -Y "http.host or tls.handshake.extensions_server_name" \
  -T fields -e frame.time_relative -e ip.dst -e http.host \
  -e tls.handshake.extensions_server_name
```

Public reporting (CYFIRMA, netmanageit, SOCPrime, GBHackers, DarkAtlas and others)
identifies this family as **Salat Stealer**, and every RE finding above matched the
published behaviour. The family's five documented hardcoded C2 domains share the URL
pattern `/sa1at/`.

After capturing the check-in, the VM's NAT link was cut
(`VBoxManage controlvm ... setlinkstate2 off`) and the VM treated as burned.

---

## 7. Infrastructure mapping (passive OSINT)

Everything below was obtained **passively** — standard DNS/WHOIS, Certificate
Transparency, and *pre-existing* third-party scans on urlscan.io. No further contact was
made with the attacker infrastructure beyond the single controlled check-in above.

**Pivoting technique that paid off:** searching urlscan.io **by IP** (not by domain)
against the real hosting IPs revealed C2 domains not present in earlier public reporting,
including a **live admin panel with its origin exposed**.

| Domain / host | Status | Fronting | Hosting / notes |
|---|---|---|---|
| `salator[.]es` | Active | Cloudflare (flagged "Suspected Malware") | origin hidden |
| `websalat[.]top` | Active | Cloudflare (flagged "Suspected Phishing") | oldest active (~2.4 y) |
| `webrat[.]top` | Active | Cloudflare | same CF range as websalat |
| `wruser[.]org` | **Active** | **None (OPSEC fail)** | **AlexHost `2.59.219[.]233` (MD)** — `WEB_RAT` login panel with self-registration |
| `webr[.]at` | Active | None | OVH `141.95.112[.]163` (DE) |
| `webrat[.]org` | Active | None | OVH `141.95.112[.]163` (DE) |
| `pidorasina[.]ru` | Active | None | REG.RU `95.163.244[.]136` (RU) |
| `salat[.]cn` | Dead / expired | — | oldest of all (~2.7 y); now parked |
| `wrat[.]in`, `wrat[.]in:992` | Dead (`serverHold`) | — | historically AlexHost + FreakHosting `185.213.240[.]179` (UK) |
| `posholnahuy[.]ru`, `webrat[.]in`, `webrat[.]su`, `nyash[.]team` | Inactive | — | — |
| **`62.109.0[.]189/login/`** | **Active admin panel** | None | **WebDC, Khimki, Russia**; live since ≥ Sep 2025 |

**The recurring OPSEC failure:** `wruser[.]org`, `webr[.]at` and `webrat[.]org` are all
registered *through* Cloudflare as registrar but do **not** use Cloudflare's proxy — so the
"marketing" domains stay hidden while the actual management panels resolve straight to
real origin IPs at abuse-tolerant hosts (AlexHost/Moldova, and OVH/Germany).

**Live panel:** `hxxps://wruser[.]org/sa1at/` returns HTTP 200 with title `WEB_RAT` and a
login/CAPTCHA screen that permits **self-registration** — the hallmark of a
Malware-as-a-Service platform where each customer provisions their own botnet.

---

## 8. Attribution

Attribution here is **group-level and drawn from public reporting** — deliberately not
naming any individual.

- The family is **Salat Stealer**, sold as **Malware-as-a-Service** by **Russian-speaking
  actors**. CYFIRMA's public report attributes the platform ("WebRat") to the groups
  **NyashTeam** and **Kapchenka**, sold via Telegram (~1,199 RUB/month subscription;
  additional hosting fee), with a reseller/affiliate model.
- **Geographic indicators** (WHOIS fields left un-redacted on independently registered
  domains): `RU / Primorskiy` and `RU / Bashkortostan`, plus `TJ` (Tajikistan) on the
  oldest domain — different registrars and dates, all pointing to a Russian-speaking /
  post-Soviet origin. WHOIS data can be falsified, so these are **corroborating
  indicators, not proof**.
- Other soft signals: a Russian-language GitHub release title, and the use of **Angie**
  (an nginx fork by a Russian company) on the exposed C2 host.

**Individual attribution is intentionally excluded from this document.** Identifying a
specific operator is a matter for law enforcement, not a public write-up.

---

## 9. Indicators of Compromise

Defanged. See [`iocs.csv`](./iocs.csv) for a machine-readable list.

**File hashes (SHA-256)**

| File | SHA-256 | Note |
|---|---|---|
| `service.exe` | `18e4b49fd7e15ca846c6346ce58268ff206974eefde55ef5998a2e9cd3b203e2` | GitHub-hosted update payload (~90,946 downloads) |
| `svhost.exe` | `ac0ef032165f08ebf92702b3c401b801e944638c81e979e29473897c69c35dff` | typosquat of `svchost.exe` (~38,733 downloads) |
| `Host.exe` | `038f1f914d23573dd748f6b58c5ffdf2f1fb964147462e1db98355d66817367a` | (~40,430 downloads) |
| `agent_payload` (decrypted stealer) | `c935e0e1f2a230b4583b8d46a607631f4f27d7b582e76a341f82d130805e0d17` | Salat Stealer, 12.5 MB PE32 |

**C2 / infrastructure domains** (defanged): `salator[.]es`, `websalat[.]top`,
`webrat[.]top`, `wruser[.]org`, `webr[.]at`, `webrat[.]org`, `pidorasina[.]ru`,
`salat[.]cn`, `wrat[.]in`, `wrat[.]in:992`, `posholnahuy[.]ru`, `webrat[.]in`,
`webrat[.]su`, `nyash[.]team` — URL pattern `/sa1at/`.

**Hosting / IPs:** `2.59.219[.]233` (AlexHost, MD), `185.213.240[.]179` (FreakHosting, UK),
`141.95.112[.]163` (OVH, DE), `95.163.244[.]136` (REG.RU, RU),
`62.109.0[.]189` (WebDC, RU — admin panel).

**Host artifacts**
- Dropped: `%APPDATA%\<random>\agent_<8-random>.exe` (hidden)
- Self-relocation: `%LOCALAPPDATA%\Temp\Staem.exe` (typosquat of `Steam.exe`)
- ChaCha20-Poly1305 key: `f222227925253d5b827a363444728c667e3fdeff5a122556cd8935893154c1ba`
- DoH resolvers abused: `1.1.1.1/dns-query`, `cloudflare-dns.com/dns-query`, `dns.google/resolve`

---

## 10. Detection & mitigation

- **Block** the domains, hosting IPs and file hashes above; treat any `/sa1at/` URL path
  as malicious.
- **Hunt** for execution of `agent_*.exe` from `%APPDATA%` subfolders and for
  `Staem.exe`/`svhost.exe` running from user-writable paths.
- **Monitor DoH** endpoints from non-browser processes — this family deliberately uses DoH
  to bypass traditional DNS logging.
- **LSASS access** from unexpected processes remains a high-value detection here.
- Treat **GitHub Releases** (and other trusted CDNs) as possible malware delivery — the
  update mechanism relies on the domain being trusted/allow-listed.
- Report the infrastructure to the relevant abuse channels (hosting providers and the
  registrar/CDN) as an independent containment step.

---

## 11. Methodology, tooling & ethics

**Tooling:** Ghidra (headless RE + custom memory-dump script), Python
(`cbor2`, `cryptography`, `zstandard`), Wireshark/`tshark`, Nmap, VirtualBox (isolated lab),
plus passive OSINT (DNS/WHOIS, Certificate Transparency, urlscan.io on pre-existing scans).

**Lab safety:** all execution happened in a disposable VM on an isolated network; internet
egress was enabled only briefly and deliberately to observe C2, then cut. The VM was
treated as burned and never reconnected to any real network.

**Ethics & disclosure:**
- Only **passive** techniques were used against live infrastructure, aside from a single
  controlled malware check-in in the lab. No attacker systems were accessed, scanned for
  exploitation, or interfered with.
- **Individual attribution and any personal data are excluded** from this public document;
  that material was documented separately and handled through law enforcement.
- IOCs are published to help defenders. This write-up is for **defensive and educational**
  purposes.

---

*Written up by eva420. Corrections and additional sightings welcome via GitHub issues.*
