# HIV-Prinsip Evasion untuk Authorized Bug Bounty Testing

> Konsep: berbaur dengan traffic normal agar WAF/IPS tidak menghalangi validasi authorized testing.
> Semua testing tetap dalam scope program H1 yang diizinkan.

---

## Tabel Analogi Biologi → Tradecraft

| Prinsip HIV | Mekanisme Biologis | Implementasi Hunting |
|---|---|---|
| **Glycan Shield** | Virus menyelubungi protein dengan glikan host — antibodi tidak mengenali sebagai "asing" | Request pattern identik dengan real user: UA, headers, timing, referer — semua sesuai fingerprint browser asli |
| **CD4 Hijacking** | HIV memasuki sel dengan memakai reseptor yang memang ada di permukaan sel — bukan merusak pintu | Gunakan endpoint yang sudah legitimate (public API, GraphQL) — jangan buat path aneh yang gak pernah ada di JS bundle |
| **Latency / Reservoir** | Virus bersembunyi dormant — sistem imun tidak scan karena tidak ada aktivitas | Jeda antar-request 30-120 detik dengan jitter random. Jangan burst. Distribusi PoC ke beberapa jam/sesi |
| **Rapid Mutation** | Selalu berubah lebih cepat dari antibodi yang baru terbentuk | Rotasi payload encoding: URL, hex, base64, mixed case, unicode — satu teknik per sesi, jangan repeat pattern yang sudah di-block |
| **Mimicry / Self-Camouflage** | Protein kapsid meniru struktur host — dibaca sebagai "self" bukan "non-self" | Browser session asli: cookie, session token, referer chain, XSRF token — semua di-set sebelum test. Request datang dari "inside" authenticated session |
| **Low Viral Load** | Aktivitas virus turun sampai tidak terdeteksi load testing — tapi tetap ada | Volume request di bawah threshold rate-limit. Satu parameter diuji per request, bukan full scan. Manual, bukan scanner |
| **Cell-to-Cell Spread** | Menular antar sel tanpa keluar ke bloodstream — tidak ada free virus untuk antibody tangkap | Pivoting internal: satu endpoint → parameter di endpoint sebelah (same session, same origin) — jangan lompat random antar domain/subdomain |
| **Integration into Host DNA** | Virus mengintegrasikan genome ke DNA host — jadi bagian dari sistem, tidak bisa dibedakan | Gunakan flow application asli: login → browse → API call → logout. Request test embed dalam normal user journey |

---

## Prinsip Operasional (untuk program crypto.com / Shopify)

### Layer 1: Glycan Shield — Request Fingerprint

```python
# ❌ Terlihat sebagai bot/scanner
headers = {
    "User-Agent": "python-requests/2.31.0",
    "Accept": "*/*",
    "Connection": "keep-alive",
}

# ✅ Terlihat sebagai real browser session
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Referer": "https://crypto.com/nft",
    "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin",
    "Upgrade-Insecure-Requests": "1",
}
```

### Layer 2: Latency — Timing Discipline

```python
import random, time

def human_delay(min_s=3, max_s=45):
    """Jeda yang meniru reading time + scroll time"""
    time.sleep(random.uniform(min_s, max_s))

def burst_avoidance():
    """Jangan pernah >3 request/detik ke target yang sama"""
    time.sleep(random.uniform(0.4, 1.2))
```

### Layer 3: Mutation — Payload Rotation

```python
# Round 1: direct
payload = "admin' OR 1=1--"

# Round 2 (jika round 1 diblokir): hex encode
payload = "0x61646d696e27204f5220313d312d2d"

# Round 3: mixed case + comment split
payload = "AdMiN'/**/OR/**/1=1--"

# Round 4: unicode normalization
payload = "admin\u0027 OR 1=1--"

# Round 5: parameter pollution
# ?param=safe&param=payload
```

### Layer 4: Cell-to-Cell — Session Pivot

```
✅ CORRECT (in-session pivot):
  Login to app → browse normal → hit /api/user/profile (test IDOR)
  → same session hit /api/user/settings (test IDOR)
  → same session hit /api/user/orders (test IDOR)

❌ WRONG (cross-domain jump — triggers anomaly detection):
  api.crypto.com → suddenly wapi.crypto.com → suddenly pay.crypto.com
  (no referer chain, no session flow)
```

### Layer 5: Integration — Embed in Real Journey

```
1. Buka https://crypto.com/ seperti user biasa (GET, full browser headers)
2. Klik NFT marketplace → session cookie set
3. Browse beberapa page → pattern terlihat "normal user"
4. Baru test: modifikasi parameter di endpoint yang SAMA
5. Jika 403/block → tunggu 30-60 menit → coba lagi dengan payload mutated
6. Semua dalam satu session yang sudah "trusted" (punya cookie + browsing history)
```

---

## Mekanisme Lanjutan (Tiga Senjata Utama HIV)

### 1. Integrasi DNA Virus — Paradoks "Bunuh Aku = Bunuh Diri Sendiri"

**Biologi:** RNA virus → reverse transcriptase → DNA → menyatu permanen ke genom sel CD4. Membunuh virus = membunuh sel inang = sistem imun menghancurkan dirinya sendiri.

**Tradecraft:** Pilih vector yang menempel pada fungsi inti infrastruktur target — sehingga mitigasi = merusak produk mereka sendiri.

| Vector | Kenapa tidak bisa diblock tanpa self-harm |
|---|---|
| OAuth `state` manipulation di `authorize` endpoint | Server gak bisa enforce state-uniqueness strict tanpa merusak flow login user (session loss, back-button break) |
| QUIC/UDP 443 ke CF edge | Kominfo gak bisa block UDP 443 tanpa memutus mayoritas web — CF serve setengah internet |
| GraphQL via public endpoint | Introspection/alias di-disable = break developer onboarding dan tooling mereka sendiri |
| Referer leak di halaman yang share social | Hilangkan referer = hilangkan analytics mereka |
| Mass-assignment di endpoint yang dipakai app mobile sendiri | Strict whitelist = break app versi lama = forced update jutaan user |

**Aturan:** sebelum menembak, tanya — *"kalau mereka patch ini, apa yang rusak di produk mereka?"* Kalau jawabannya "tidak ada yang rusak", vector itu mudah dimatikan → cari yang lebih struktural. Kalau jawabannya "login/UX/analytics rusak" → itu vector yang bertahan lama dan layak diinvestigasi dalam.

### 2. Reservoir Laten — Foothold Dormant

**Biologi:** Virus bersembunyi inactive di sel-sel imun, tidak terjangkau obat maupun deteksi. Berhenti obat → viral rebound dari reservoir.

**Tradecraft:** Stage, jangan fire. Foothold yang tidak aktif tidak muncul di log anomaly.

| Bentuk reservoir | Implementasi |
|---|---|
| Akun verified + idle | Akun kedua dibuat + verified, lalu dibiarkan tidak dipakai 3-7 hari → tidak ada anomali di log sampai dipakai |
| Payload planted | Stored XSS / comment / profile field berisi payload tapi TIDAK ditrigger — menunggu validation window |
| Vector cadangan | 3-4 jalur test berbeda (QUIC, browser session, mobile IP) — kalau satu kena flag, yang lain bersih |
| Evidence staged | Data PoC (3 record, bukan 3000) dikumpulkan dulu, exfil-proof ditunda sampai report siap |
| Session token parkir | Session disimpan di state file, dipakai lagi next-day — masih warm, tidak trigger new-login alert |

**Aturan:** jangan pernah fire semua vector sekaligus. Kumpulkan foothold → diam → tungal tembakan per validation. Aktivitas burst = keluar dari reservoir = terlihat.

### 3. Mutasi Sangat Cepat — Outpace Rule Updates

**Biologi:** Reverse transcriptase tanpa proofreading → 1 mutasi per replikasi → varian baru lebih cepat dari antibodi yang baru terbentuk.

**Tradecraft:** WAF rule update per-sprint/per-config-change. Kita mutate per-request. Signature-based detection SELALU reactive — mereka harus melihat bentuk dulu sebelum bisa block.

```
Semantik payload: TETAP SAMA (bug yang sama diuji)
Sintaks payload : TIDAK PERNAH BERULANG

Round 1: admin' OR 1=1--
Round 2: 0x61646d696e27204f5220313d312d2d      (hex)
Round 3: aDmIn'/**/Or/**/1=1--                  (case+comment)
Round 4: admin%27%20OR%201%3D1--                (full URL-encode)
Round 5: admin\u0027 OR 1=1--                    (unicode)
Round 6: JSON: {"u":"admin","p":{"$ne":""}}      (parser confusion)
Round 7: admin'+OR+'1'='1                       (quote-wrapped)
Round 8: parameter pollution: ?u=admin&u=' OR 1=1--
```

**Aturan:** payload yang sudah kena block TIDAK PERNAH dikirim ulang dalam bentuk yang sama — itu hanya mengkonfirmasi ke WAF bahwa rule mereka bekerja. Setiap retry = bentuk baru. Kalau satu teknik habis (semua varian blocked), tunggu rule-decay (WAF rules sering dilonggarkan setelah campaign selesai) atau pindah ke vector struktural (mekanisme 1).

---

## Anti-Patterns (yang bikin ketahuan)

| Yang memicu deteksi | Kenapa |
|---|---|
| `sqlmap`, `nikto`, `nuclei` default config | Signature scanner dikenali CF WAF dalam 1-2 request |
| Burst 50+ request dalam <5 detik | Anomaly threshold — CF block IP |
| Path yang tidak ada di JS bundle/sitemap | 404-flood detection → IP flagged |
| User-Agent kosong atau `python`/`curl` | Bot fingerprint — instant challenge page |
| Test dari VPN/datacenter IP | IP reputation — CF risk score tinggi |
| Missing Referer on POST request | CSRF pattern — flag anomalous |
| Same payload repeated after block | Persistent threat classification — IP ban |

---

## Ringkasan Prinsip

> **"Test seperti user, bukan seperti mesin."**

1. **Request kamu harus tidak bisa dibedakan** dari user yang sedang browse biasa
2. **Jangan pernah trigger threshold** — volume test di bawah rate-limit normal user
3. **Ketika di-block, jangan insist** — mutasi payload, jeda, pivot ke endpoint lain
4. **Semua test dalam session asli** yang punya browsing history dan cookies
5. **Jangan scan breadth** — targeted, satu parameter, satu endpoint, satu sesi

---

## Ethical Note

Ini bukan evasion dari authorization — semua testing tetap dalam scope H1 program yang sudah menerima kamu sebagai researcher. Prinsip ini hanya menjaga:
1. WAF tidak menghalangi validasi yang legitimate
2. Triager tidak mengira kamu adalah malicious actor
3. Test kamu bisa selesai sebelum IP ke-block oleh CDN

Program menerima report dari tools seperti Burp Suite — tapi yang dibicarakan di sini adalah level operational yang lebih tinggi: **disiplin agar test kamu sustainable** dan tidak merusak akses untuk sesi berikutnya.
