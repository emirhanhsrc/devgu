# DEVGU TODO

Durum: Aşama 0–6 tamamlandı (yayın hariç). Kapsam bilinçli olarak daraltıldı; ayrıntı için [ROADMAP.md](ROADMAP.md).
Kural: her aşamada testler geçer, sahte bulgu/istatistik yok.

## Aşama 0 — Blueprint ✅

- [x] ARCHITECTURE.md (paketler, hat, Finding modeli, taint özeti, riskler)
- [x] Tehdit modeli ([docs/THREAT_MODEL.md](docs/THREAT_MODEL.md))
- [x] Kural kataloğu ([docs/RULES.md](docs/RULES.md), koddan üretilir)

## Aşama 1 — Çekirdek ✅

- [x] Monorepo, TypeScript, Vitest, ESLint, Prettier
- [x] Finding şeması (Zod), parmak izi, maskeleme
- [x] Güvenli keşif: sembolik bağlantı yok, boyut/dosya/satır sınırları, dışlamalar
- [x] Babel ile JS/TS/JSX/TSX, hata toleransı
- [x] İçerik özetli önbellek (kullanıcı önbellek dizininde)
- [x] CLI: `scan`, `rules`, `config init`, `cache clear`, `version`; çıkış kodları
- [x] Zafiyetli ve güvenli fixture projeler + golden testler

## Aşama 2 — Güvenlik temeli ✅

- [x] Kural motoru (etkinleştirme, şiddet geçersiz kılma, tek geçişli AST ziyaretçileri)
- [x] 11 AST kuralı (XSS, kod yürütme, URL, postMessage, depolama, yapılandırma)
- [x] Secret scanner (10 kural, entropi, maskeleme, allowlist)
- [x] Gerekçeli bastırma (satır içi + yapılandırma)
- [x] JSON ve SARIF 2.1.0

## Aşama 3 — Taint analizi ✅

- [x] Kaynak / sink / temizleyici modeli, veri akışı yolu
- [x] Güven seviyesi (URL kaynağı HIGH, postMessage MEDIUM, form alanı LOW)
- [x] "Tehlikeli görünen ama güvenli" fixture'lar
- [x] Sınırlamalar dokümante edildi
- [ ] Fonksiyonlar arası (inter-procedural) ve dosyalar arası akış → [ROADMAP.md](ROADMAP.md)

## Aşama 4 — Bağımlılık güvenliği ✅ (npm)

- [x] `package-lock.json` v1/v2/v3
- [x] OSV + çevrimdışı önbellek, CVSS v3, varsayılan çevrimdışı (`--online` ile)
- [x] Zafiyet bulguları ile güncel olmayan paket uyarıları ayrı (yalnızca zafiyet)
- [x] Gerçek OSV yanıtıyla uçtan uca doğrulama
- [ ] `yarn.lock`, `pnpm-lock.yaml`, lisans bilgisi → [ROADMAP.md](ROADMAP.md)

## Aşama 5 — Rapor ✅

- [x] Tek dosyalık HTML rapor (CSP, `textContent`, jsdom ile XSS testi)
- [x] Markdown rapor (kaçışlı, güvenli kod çiti)
- [x] Rapor metaverisi: sürüm, kural seti, tarih, motorlar, sayılar, bastırılanlar
- [x] Çok dilli çıktı (TR/EN): `--lang` + config, tüm kural/akış/rapor/CLI metinleri, `meta.lang`, iki dilli kural kataloğu
- [ ] Import grafı ve döngüsel bağımlılık (isteğe bağlı) → [ROADMAP.md](ROADMAP.md)

## Aşama 6 — Yayın hazırlığı ✅ (npm yayını hariç)

- [x] CI: Node 20/22/24 × Linux/Windows, lint, biçim, test, paket doğrulama
- [x] Kendi kendini tarama + SARIF yükleme + `npm audit`
- [x] Sürüm iş akışı (etiketle tetiklenir, NPM_TOKEN yoksa yayınlamaz)
- [x] Dependabot, issue/PR şablonları
- [x] LICENSE, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, CHANGELOG, ROADMAP
- [x] Gerçek ölçümler ([docs/BENCHMARKS.md](docs/BENCHMARKS.md))
- [x] Kendi bağımlılık ağacında OSV ile bulunan advisory'ler giderildi (zod 4, vitest 5, minimatch 11)
- [ ] `v0.1.0` etiketi ve npm yayını (geri alınamaz; sahibinin kararı)
- [ ] Demo GIF/video

## Sürekli

- [x] Her kural fixture + testle gelir
- [x] Tamamlanmamış özellik README'de "Planlı" / "Kapsam dışı" olarak işaretli
- [x] ReDoS'a dayanıklı regex'ler, parser kaynak limitleri, güvenli geçici dosya
