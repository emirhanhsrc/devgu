# DEVGU

**Kodunuzu anlayın. Yazılımınızı güvenceye alın.**

DEVGU; yapay zekâ kullanmayan, yerel çalışan ve deterministik bir kod güvenliği analiz aracıdır. JavaScript / TypeScript / React projelerini statik olarak inceler; DOM tabanlı XSS gibi veri akışı zafiyetlerini, tehlikeli API kullanımlarını, ifşa olmuş gizli anahtarları ve zafiyetli bağımlılıkları bulur. Her bulguyu kanıtıyla, nedeniyle, çözüm önerisiyle ve **tespitin sınırlarıyla** raporlar.

---

## Neden DEVGU?

| İlke                | Anlamı                                                                                                |
| ------------------- | ----------------------------------------------------------------------------------------------------- |
| **Yapay zekâsız**   | Hiçbir LLM veya dış yapay zekâ servisi kullanılmaz. Her bulgu açık bir kural veya algoritmadan gelir. |
| **Deterministik**   | Aynı kod ve aynı yapılandırma her zaman aynı sonucu üretir.                                           |
| **Açıklanabilir**   | Her bulgu; ne bulunduğunu, neden riskli olduğunu, kanıtı, çözümü ve sınırlamalarını içerir.           |
| **Yerel çalışır**   | Kaynak kod makinenizden çıkmaz. Ağ erişimi varsayılan olarak kapalıdır.                               |
| **Güvenli tasarım** | Taranan depo güvenilmez girdi sayılır; kodu asla çalıştırılmaz.                                       |
| **Dürüst**          | Tehlikeli görünen her API "doğrulanmış zafiyet" sayılmaz; güven seviyesi (confidence) belirtilir.     |

## Özellikler

| Özellik                                                                                              | Durum                             |
| ---------------------------------------------------------------------------------------------------- | --------------------------------- |
| Güvenli depo keşfi (sembolik bağlantı izlenmez, boyut ve dosya sayısı sınırları, özel dışlamalar)    | Hazır                             |
| JS / TS / JSX / TSX ayrıştırma (Babel), bozuk dosyalarda dayanıklılık                                | Hazır                             |
| 11 güvenlik kuralı: XSS, `eval`/`Function`, `javascript:` URL, `postMessage`, depolama, yapılandırma | Hazır                             |
| Gizli anahtar tarama: 10 kural, desen + entropi, çıktıda maskeleme                                   | Hazır                             |
| Taint analizi: kaynak → sink veri akışı yolu, temizleyiciler, güven seviyesi (tek dosya içi)         | Hazır                             |
| Bağımlılık güvenliği: `package-lock.json` + OSV, CVSS v3, çevrimdışı önbellek                        | Hazır                             |
| Raporlar: metin, JSON, **SARIF 2.1.0**, Markdown, CSP korumalı tek dosyalık **HTML**                 | Hazır                             |
| Gerekçeli bastırma, artımlı önbellek, anlamlı çıkış kodları                                          | Hazır                             |
| `yarn.lock` / `pnpm-lock.yaml`, fonksiyonlar arası taint, import grafı ve döngüsel bağımlılık        | Planlı ([ROADMAP.md](ROADMAP.md)) |
| Masaüstü arayüzü, eklenti SDK'sı, performans/karmaşıklık motorları                                   | Kapsam dışı                       |

26 kuralın tamamı [docs/RULES.md](docs/RULES.md) içinde; `devgu rules explain <id>` ile terminalde de okunur.

## Kurulum ve ilk tarama

Gereksinimler: Node.js 20+ ve npm.

```bash
git clone https://github.com/emirhanhsrc/devgu.git
cd devgu
npm ci
npm run build
node apps/cli/dist/index.js scan fixtures/vulnerable
```

Tek dosyalık dağıtım paketi için: `npm run bundle` → `dist-bundle/devgu.mjs` (npm'e yayın sürüm etiketiyle yapılır).

## Kullanım

```bash
devgu scan .                                  # tüm motorlarla tara
devgu scan ./src --security                   # yalnızca güvenlik + taint kuralları
devgu scan . --secrets                        # yalnızca gizli anahtar taraması
devgu scan . --dependencies --online          # OSV ile zafiyetli bağımlılıklar
devgu scan . -f sarif -o devgu.sarif          # GitHub Code Scanning için
devgu scan . -f html -o rapor.html            # tek dosyalık HTML rapor
devgu scan . --fail-on medium                 # MEDIUM ve üstünde çıkış kodu 1
devgu rules list
devgu rules explain JS-TAINT-001
devgu config init                             # devgu.config.json oluştur
devgu cache clear
```

Çıkış kodları: `0` başarılı, `1` eşik üstü bulgu var, `2` kullanım hatası, `3` çalışma hatası, `130` iptal.

**Ağ erişimi:** yalnızca `--online` verilirse ve yalnızca `api.osv.dev` adresine, sadece paket adı ve sürümleri gönderilir. Kaynak kod hiçbir zaman gönderilmez. Sonuçlar yerel önbelleğe yazılır; sonraki taramalar çevrimdışı çalışır.

### Örnek bulgu

```
src/search.jsx
  6  HIGH     HIGH   JS-TAINT-001  DOM-based XSS: untrusted data reaches an HTML sink (source: location.search)
      document.getElementById("greeting").innerHTML = html;
      -> src/search.jsx:3 Source: location.search
      -> src/search.jsx:4 Result of .get()
      -> src/search.jsx:5 Interpolated into a template string
      -> src/search.jsx:6 Sink: innerHTML assignment
```

### Bastırma

Yalnızca gerekçeyle bastırılır; gerekçesiz yorum hiçbir şeyi bastırmaz ve bastırılan bulgular raporlarda görünür kalır.

```js
// devgu-ignore JS-XSS-001: içerik yalnızca derleme zamanında üretilen sabit şablon
el.innerHTML = template;
```

Parmak izi ile yapılandırmada: `devgu.config.json` → `suppressions: [{ "fingerprint": "...", "justification": "..." }]`.

### CI entegrasyonu

SARIF çıktısı GitHub Code Scanning ile uyumludur. Bu depo kendi kodunu ve bağımlılıklarını aynı yolla tarar:
[.github/workflows/security.yml](.github/workflows/security.yml).

## Mimari

```
devgu/
├── apps/cli/                CLI (ince katman)
├── packages/
│   ├── shared/              Finding modeli, şemalar, parmak izi, maskeleme
│   ├── parser/              Babel ayrıştırıcı ve AST yardımcıları
│   ├── rule-engine/         Kural sözleşmesi, çalıştırıcı, güvenlik kuralları
│   ├── secret-scanner/      Gizli anahtar kuralları ve maskeleme
│   ├── taint-analysis/      Veri akışı (taint) motoru
│   ├── dependency-engine/   Kilit dosyası, OSV istemcisi, CVSS
│   ├── report-engine/       Metin / JSON / SARIF / Markdown / HTML
│   └── core/                Keşif, yapılandırma, önbellek, analiz hattı
├── fixtures/                Zafiyetli ve güvenli örnek projeler (golden testler)
└── docs/                    Mimari, tehdit modeli, kural kataloğu, ölçümler
```

Ayrıntılar: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Güvenlik yaklaşımı

DEVGU, taradığı kod tarafından istismar edilememelidir. Başlıca önlemler:

- Taranan dosyalar yalnızca metin olarak okunur; betik, derleme adımı veya eklenti çalıştırılmaz.
- Sembolik bağlantılar izlenmez; kök dışına çıkış engellenir.
- Dosya boyutu, dosya sayısı ve satır uzunluğu sınırlıdır; düzenli ifadeler doğrusal zamanlıdır.
- Gizli anahtarlar tespit anında maskelenir ve tüm çıktılarda ikinci kez taranıp maskelenir.
- Önbellek taranan depoya değil, kullanıcı önbellek dizinine yazılır ve doğrulanır.
- HTML raporu sıkı bir CSP ile üretilir; rapor jsdom ile gerçekten çalıştırılarak XSS testinden geçirilir.
- Terminal çıktısından kaçış dizileri temizlenir.

Tehdit modeli: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Açık bildirimi: [SECURITY.md](SECURITY.md).

## Sınırlamalar

- Taint analizi **tek dosya içindedir**; fonksiyon çağrıları, dosyalar arası akışlar ve `fetch` yanıtları izlenmez. Bulgunun olmaması güvenlik kanıtı değildir.
- Frontend analizi, sunucu tarafı yetkilendirme veya sunucu güvenliği hakkında bir şey söyleyemez.
- Yalnızca kök `package-lock.json` denetlenir.
- Gizli anahtar taraması sezgiseldir; zayıf gerçek parolalar kaçabilir, rastgele görünen kimlikler işaretlenebilir.

Her kuralın sınırları `limitations` alanında yazılıdır.

## Performans

3000 dosya / 132 bin satırlık sentetik projede soğuk tarama ~8,9 sn, değişmemiş projede önbellekli tarama ~1,3 sn.
Yöntem ve sınırlar: [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Geliştirme

```bash
npm ci
npm run check     # build + lint + test
npm run bench     # performans ölçümü
```

Katkı rehberi: [CONTRIBUTING.md](CONTRIBUTING.md) · Değişiklikler: [CHANGELOG.md](CHANGELOG.md) · Yol haritası: [ROADMAP.md](ROADMAP.md)

## Lisans

[MIT](LICENSE)
