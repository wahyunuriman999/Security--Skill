# LESSONS.md — Engagement Learning Ledger

Format: `- [KELAS] trigger → lesson → fix konkret`

## WAF / Evasion
- [WAF] CF edge TCP 8443 → block TLS fingerprint (bukan IP) → gunakan QUIC/UDP 443 via aioquic, header :authority wajib
- [TARGET] Kominfo DNS-hijack crypto.com ke HIJACK_IP + SNI-MITM TCP 443 → QUIC bypass middlebox TCP-only

## Report Quality
- [REJECT] CORS wildcard tanpa ACAC di NFT GraphQL → pre-submission review: "multiple findings not focused" → satu report = satu vuln, bukti HTTP mentah + PoC lengkap
- [REJECT] Weakness dropdown tidak ada CSRF → pilih CWE terdekat (Improper Access Control), jelaskan root cause di body

## Tooling
- [TOOL] scratch dir di-prune tiap 24 jam → rat_h3.py hilang → simpan tool penting di bountyforge-hunt/tools/, bukan scratch
- [TOOL] vision_analyze gagal baca screenshot → auxiliary.vision.provider belum diset → `hermes config set auxiliary.vision.provider main`

## Techniques
- [TECHNIQUE] state reuse di Okta authorize: state sama + nonce beda = 200/200, state kosong = 302 error → pola "presence but not uniqueness" khas Okta
- [TECHNIQUE] OOB callback: webhook.site token + tag-based poll → `rat_oob.py wait <tag>` untuk blind SSRF/XSS/LLM-exfil
- [TECHNIQUE] HIV principle → tradecraft: glycan shield (fingerprint), latency (jitter), mutation (payload rotation), integration (vector struktural), reservoir (stage jangan fire)

## Chain Investigation (2026-10-11)
- [TECHNIQUE] OIDC chain recon order yang cepat: redirect_uri whitelist → PKCE enforcement → state persistence di login page → callback differential → discovery doc grant_types. 5 probe = peta lengkap defense surface
- [TARGET] Okta discovery doc mengiklankan 'password' grant di employee IdP — info berguna buat attack surface narrative, bukan langsung bug
- [TECHNIQUE] state yang embed di fromURI hidden field = bukti state survive seluruh login journey — ini yang bikin login-CSRF credible, bukan cuma state reuse
- [WAF] Shopify infra (okta + shopifycloud.com) tidak block probe anon sama sekali — tidak perlu HIV-mode untuk target ini; glycan shield cukup
- [REJECT] redirect_uri strict whitelist (400 semua) = jangan paksakan exfil OOB; fokus ke chain CSRF + PKCE-gap sebagai severity driver
- [TECHNIQUE] callback differential (code+state=halaman error penuh vs state kosong=body kosong) = sinyal parser behavior tanpa perlu akun

## Differential & Cache Skills (2026-10-14)
- [TECHNIQUE] Method-differential 7 verbs × 1 route bisa jalan standalone (tanpa plugin proxy Caido/Burp) dan tetap menemukan satu-satunya method-inconsistency target tanpa kredensial test → bangun mesin deteksi sendiri kalau dependency ekstensi tidak tersedia, jangan skip kelas bug ini
- [REJECT] Divergensi status code saja (GET 200 vs HEAD/OPTIONS 401) dengan body kecil dan non-sensitif = observasi, bukan vulnerability → syarat submit: nilai yang bocor, aksi write 2xx, chain ke state change, atau inkonsistensi terhadap sibling route; selain itu turunkan ke catatan
- [TECHNIQUE] Detektor yang menandai SETIAP 200 tampak sehat padahal noise → wajib pasang negative control (fixture routine 200 harus bersih) sebelum mengklaim alat jalan; tanpa itu false-positive rate tak terukur
