---
name: engagement-learning-loop
version: 1.0.0
author: serigalamalem + user
license: MIT
description: "After every hunt event, append a lesson to LESSONS.md."
metadata:
  hermes:
    tags: [bug-bounty, learning, post-engagement, tradecraft]
    related_skills: [triage-validation, redteam-mindset, evidence-hygiene]
---

# Engagement Learning Loop

## When to Use

- A report was submitted, rejected, downgraded, or paid
- A technique got blocked by WAF/rate-limit/anomaly detection
- A tool or script failed or behaved unexpectedly
- The target changed behavior mid-engagement (patch, new WAF rule, endpoint died)
- A new technique was learned (repo, paper, improvisation)
- ANY event worth remembering for the next engagement

Skill ini adalah memori belajar khusus untuk setiap pengujian (engagement).
Setelah setiap kejadian penting — laporan ditolak, pengiriman berhasil (submission), terblokir WAF, alat gagal, perilaku target, teknik baru — tambahkan (append) satu baris pelajaran (lesson) ke `LESSONS.md` (file pendamping skill ini).

## Format — satu baris per pelajaran

```
- [KELAS] trigger → lesson → fix konkret
```

Kelas pelajaran (pilih satu):
- `[REJECT]` — laporan ditolak/diturunkan tingkatnya (downgrade): kenapa, dan gate mana yang seharusnya menangkapnya
- `[WIN]` — laporan diterima/dibayar: pola apa yang membuat triager setuju
- `[WAF]` — teknik diblokir (block): bentuk payload/traffic yang memicu deteksi, dan mutasi (mutation) apa yang berhasil lolos
- `[TOOL]` — alat/skrip gagal atau berperilaku aneh: gejala + akar masalah (root cause) + perbaikan
- `[TARGET]` — perilaku target yang tidak terduga (perubahan rate-limit, JS bundle berubah, endpoint mati, patch di tengah pengujian)
- `[SCOPE]` — pelajaran batas program (apa yang ternyata di luar cakupan/OOS, apa yang ternyata OK)
- `[TECHNIQUE]` — teknik baru yang terbukti berhasil

## Aturan
1. Tulis pelajaran SEGERA setelah kejadian selesai — semakin baru, semakin akurat.
2. Satu baris = satu pelajaran. Tiga pelajaran dari satu kejadian = tulis tiga baris.
3. Perbaikan harus konkret: bukan "hati-hati", tetapi "tambahkan pemeriksaan (check) X sebelum mengirim (send) Y".
4. Baca LESSONS.md sebelum memulai pengujian baru — cari kelas target/teknik yang sama.
5. Lakukan penghapusan duplikat (dedup) sebelum menambahkan (append) — jika pelajaran serupa sudah ada, perbarui baris lama.
6. Riwayat mutasi (mutation-history) juga dicatat di sini — payload yang pernah diblokir tidak pernah dikirim ulang dalam bentuk yang sama.

## Seed lessons (dari pengujian (engagement) crypto.com/Shopify kita — salin ke LESSONS.md saat inisialisasi (init))

```
- [WAF] CF edge TCP 8443 → blokir TLS fingerprint (bukan IP) → gunakan QUIC/UDP 443 via aioquic, header :authority wajib
- [TARGET] Kominfo membajak DNS (DNS-hijack) crypto.com ke HIJACK_IP + SNI-MITM TCP 443 → QUIC melewati middlebox yang hanya bekerja di lapisan TCP
- [REJECT] CORS wildcard tanpa ACAC di NFT GraphQL → pre-submission review: "multiple findings not focused" → satu laporan = satu vuln, bukti HTTP mentah + PoC lengkap
- [TOOL] folder scratch dipangkas (prune) setiap 24 jam → rat_h3.py hilang → simpan alat penting di bountyforge-hunt/tools/, bukan di scratch
- [TECHNIQUE] state reuse di Okta authorize: state sama + nonce beda = 200/200, state kosong = 302 error → pola "presence but not uniqueness" khas Okta
- [REJECT] Weakness dropdown tidak ada CSRF → pilih weakness berbasis CWE yang paling dekat (Improper Access Control) lalu jelaskan akar masalah (root cause) di bagian body
```

## Cara pakai

Saat kejadian selesai:
1. Muat (load) skill ini → tambahkan (append) pelajaran ke LESSONS.md melalui aksi `write_file` pada `skill_manage`
2. Sebelum pengujian baru: baca LESSONS.md, cari kelas yang relevan

Pelajaran tidak pernah dihapus — hanya diperbarui jika terbukti salah, atau digabungkan (merge) jika duplikat.