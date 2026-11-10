# DEVGU TODO

Kaynak: README.md. Kapsam bilinçli olarak daraltıldı: önce Milestone 1-3 + lockfile için OSV eşleşmesi + HTML rapor.
Kural: her aşamada testler geçmeli, sahte bulgu/istatistik yok, bir sonraki aşamaya ancak önceki doğrulanınca geç.

## MVP dışı (şimdilik yapma)
Tauri masaüstü, plugin SDK, performance-engine, complexity-engine, duplicate code, architecture layer kuralları, inter-procedural/cross-file taint, SWC, worker tabanlı analiz, scan history UI.

---

## Aşama 0 — Blueprint
- [ ] ARCHITECTURE.md: paket sorumlulukları, analiz pipeline'ı, Finding şeması, taint algoritması önerisi, riskler
- [ ] İlk kural kataloğu (ID, kategori, severity, confidence) — yalnızca MVP kuralları
- [ ] Bilinen sınırlamalar bölümü (statik analiz neyi kanıtlayamaz)

## Aşama 1 — Çekirdek (Milestone 1)
- [ ] Monorepo (npm workspaces), TypeScript, Vitest, ESLint/Prettier
- [ ] Yalnızca gerçekten kullanılan paketler: `core`, `parser`, `rule-engine`, `shared`, `cli` (boş paket oluşturma)
- [ ] `Finding` şeması (id, ruleId, engine, severity, confidence, category, dosya/satır, evidence, remediation, references, fingerprint, status) + Zod doğrulama
- [ ] Repo keşfi: dosya sınıflandırma, filtreleme (node_modules, dist vb.), dosya boyutu limiti
- [ ] Güvenlik: path traversal, symlink kontrolü, repo kodunu/script'lerini asla çalıştırma
- [ ] Babel Parser ile JS/TS/JSX/TSX, ESM + CommonJS; parse hatasında çökmeden devam
- [ ] İçerik hash'li cache (artımlı tarama temeli)
- [ ] CLI iskeleti: `devgu scan <path>`, `devgu version`, anlamlı çıkış kodları, ilerleme çıktısı
- [ ] Zafiyetli ve güvenli fixture projeler (`fixtures/`)

## Aşama 2 — Güvenlik temeli (Milestone 2)
- [ ] Kural motoru: kural tanımı (id, ad, açıklama, severity, confidence, mantık, remediation, referans), enable/disable, severity override, hariç tutma
- [ ] `devgu rules list`, `devgu rules explain <id>`
- [ ] Kurallar (her biri: pozitif, negatif, edge ve yanlış-pozitif testi):
  - [ ] `innerHTML` / `outerHTML` / `insertAdjacentHTML` / `document.write` / `dangerouslySetInnerHTML`
  - [ ] `eval`, `new Function`, string tabanlı `setTimeout/setInterval`
  - [ ] `javascript:` URL ve güvensiz dinamik `href`
  - [ ] `postMessage`: wildcard origin, alıcıda origin doğrulaması yok
  - [ ] localStorage/sessionStorage'a token yazımı (kesin zafiyet olarak işaretleme, düşük confidence)
- [ ] Secret scanner: pattern + entropy, bağlam filtresi, allowlist, fingerprint; çıktıda secret maskeleme, logda asla tam secret yok
- [ ] Bulgu normalizasyonu + tekrar eleme
- [ ] Gerekçeli suppression (`devgu-ignore` benzeri)
- [ ] Raporlama: JSON + SARIF 2.1.0 (GitHub Code Scanning ile doğrula)
- [ ] `devgu scan --format sarif|json`

## Aşama 3 — Taint analizi (Milestone 3)
- [ ] Source / sink / sanitizer tanımları (yapılandırılabilir): `location.search/hash`, `URLSearchParams.get`, `window.name`, `postMessage` verisi → DOM sink'leri
- [ ] Scope analizi + sembol çözümleme
- [ ] Intra-procedural taint: atama, string interpolation/concat, template literal propagasyonu
- [ ] Bulguda tam yol: kaynak dosya/satır, sink dosya/satır, dönüşümler, sanitizer bilgisi
- [ ] Confidence sınıflandırması (kanıtlanmış akış = HIGH, şüpheli API = LOW)
- [ ] "Tehlikeli görünen ama güvenli" fixture'ları: analiz bunları raporlamamalı
- [ ] Dokümante edilmiş sınırlamalar

## Aşama 4 — Bağımlılık güvenliği (daraltılmış Milestone 4)
- [ ] `package-lock.json` parser (doğrudan + geçişli bağımlılıklar)
- [ ] OSV eşleşmesi + offline cache (ağ erişimi açıkça kontrollü, varsayılan kapalı/opt-in)
- [ ] Zafiyet bulgularını "outdated" uyarılarından ayır
- [ ] Bağımlılıkları asla otomatik güncelleme
- [ ] (Sonra) yarn.lock / pnpm-lock.yaml, lisans bilgisi

## Aşama 5 — Rapor ve arayüz
- [ ] Tek dosyalık HTML rapor: bulgu listesi, severity/confidence/kategori filtreleri, kod parçacığı, taint yolu, remediation
- [ ] Rapor meta verisi: scanner sürümü, kural seti sürümü, tarih, aktif motorlar, sayılar, bastırılan bulgular
- [ ] (İsteğe bağlı) Basit import grafı + döngüsel bağımlılık tespiti (Tarjan SCC)

## Aşama 6 — Yayın
- [ ] Zafiyetli demo repo üzerinde uçtan uca çalışma + beklenen bulgu assertion'ları
- [ ] Ölçüm: taranan dosya, parse süresi, kural süresi, cache hit oranı (desteklenmeyen performans iddiası yok)
- [ ] CI: lint, test, build, kendi kodunda güvenlik taraması; GitHub Action örneği ile SARIF yükleme
- [ ] README, LICENSE (MIT), CONTRIBUTING, SECURITY, CHANGELOG, ROADMAP
- [ ] Kısa demo (GIF/video) ve ilk sürüm (npm yayını)

## Sürekli
- [ ] Her kural fixture + testle birlikte gelir; testsiz kural eklenmez
- [ ] Tamamlanmamış özelliği experimental/unavailable olarak işaretle, sahte buton/veri yok
- [ ] Güvenlik: ReDoS'a dayanıklı regex, parser kaynak limitleri, güvenli geçici dosya
