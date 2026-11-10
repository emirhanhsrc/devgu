# DEVGU

**Kodunuzu anlayın. Yazılımınızı güvenceye alın.**

DEVGU; yapay zekâ kullanmayan, yerel çalışan ve deterministik bir kod zekâsı ve güvenlik analizi platformudur. JavaScript / TypeScript / React projelerini statik olarak inceler; güvenlik açıklarını, ifşa olmuş gizli anahtarları ve zafiyetli bağımlılıkları bulur. Her bulguyu kanıtıyla, nedeniyle ve çözüm önerisiyle raporlar.

> **Durum:** Aktif geliştirme aşamasında. Aşağıdaki tabloda yalnızca "Hazır" işaretli özellikler çalışır durumdadır.

---

## Neden DEVGU?

| İlke                | Anlamı                                                                                                |
| ------------------- | ----------------------------------------------------------------------------------------------------- |
| **Yapay zekâsız**   | Hiçbir LLM veya dış yapay zekâ servisi kullanılmaz. Her bulgu açık bir kural veya algoritmadan gelir. |
| **Deterministik**   | Aynı kod ve aynı yapılandırma her zaman aynı sonucu üretir.                                           |
| **Açıklanabilir**   | Her bulgu; ne bulunduğunu, neden riskli olduğunu, kanıtı, çözümü ve tespitin sınırlarını içerir.      |
| **Yerel çalışır**   | Kaynak kod makinenizden çıkmaz. Ağ erişimi varsayılan olarak kapalıdır.                               |
| **Güvenli tasarım** | Taranan depo güvenilmez girdi sayılır; kodu asla çalıştırılmaz.                                       |
| **Dürüst**          | Tehlikeli görünen her API "doğrulanmış zafiyet" olarak raporlanmaz; güven seviyesi belirtilir.        |

## Özellikler ve durum

| Özellik                                                        | Durum     |
| -------------------------------------------------------------- | --------- |
| Monorepo altyapısı, derleme, test, lint                        | Hazır     |
| Depo keşfi (güvenli gezinme, dışlamalar, boyut limitleri)      | Planlandı |
| JS / TS / JSX / TSX ayrıştırma (Babel)                         | Planlandı |
| Güvenlik kuralları (XSS, `eval`, URL, `postMessage`, depolama) | Planlandı |
| Gizli anahtar tarama (desen + entropi, maskeleme)              | Planlandı |
| Taint analizi (kaynak → sink veri akışı)                       | Planlandı |
| Bağımlılık güvenliği (`package-lock.json` + OSV)               | Planlandı |
| JSON, SARIF 2.1.0, Markdown ve HTML raporları                  | Planlandı |

Ayrıntılı iş listesi için [TODO.md](TODO.md) dosyasına bakın.

## Mimari

```
devgu/
├── apps/
│   └── cli/                 Komut satırı arayüzü (ince katman)
├── packages/
│   ├── shared/              Finding modeli, şemalar, parmak izi, maskeleme
│   ├── parser/              Babel tabanlı ayrıştırıcı
│   ├── rule-engine/         Kural sözleşmesi, çalıştırıcı, desen/AST kuralları
│   ├── secret-scanner/      Gizli anahtar kuralları
│   ├── taint-analysis/      Veri akışı (taint) motoru
│   ├── dependency-engine/   Kilit dosyası ayrıştırma, OSV istemcisi
│   ├── report-engine/       JSON / SARIF / Markdown / HTML çıktıları
│   └── core/                Keşif, yapılandırma, önbellek, analiz hattı
├── fixtures/                Zafiyetli ve güvenli örnek projeler
└── docs/                    Mimari ve tehdit modeli
```

Analiz mantığı CLI içinde değil, bağımsız paketlerde bulunur. Ayrıntılar: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Güvenlik yaklaşımı

DEVGU, taradığı kod tarafından istismar edilememelidir. Başlıca önlemler:

- Taranan dosyalar yalnızca metin olarak okunur; hiçbir betik, derleme adımı veya eklenti çalıştırılmaz.
- Sembolik bağlantılar izlenmez; yol aşımı (path traversal) engellenir.
- Dosya boyutu, dosya sayısı ve satır uzunluğu sınırlıdır; ReDoS'a dayanıklı desenler kullanılır.
- Gizli anahtarlar tespit anında maskelenir; çıktılarda tam değer asla yer almaz.
- HTML raporu katı bir içerik güvenlik politikası (CSP) ile üretilir.
- Ağ erişimi yalnızca `--online` ile ve yalnızca `api.osv.dev` için açılır.

Tam tehdit modeli: [docs/SECURITY.md](docs/SECURITY.md).

## Kurulum ve geliştirme

Gereksinimler: Node.js 20+ ve npm.

```bash
npm install
npm run build
npm test
npm run lint
```

Tüm kontroller için: `npm run check`.

## Kullanım (hedef arayüz)

```bash
devgu scan .                               # tüm motorlarla tara
devgu scan --format sarif -o out.sarif .
devgu scan --dependencies --online .       # OSV ile zafiyetli bağımlılık kontrolü
devgu rules list
devgu rules explain JS-XSS-001
devgu version
```

Çıkış kodları: `0` başarılı, `1` eşik üstü bulgu var, `2` kullanım hatası, `3` çalışma hatası.

## Yol haritası

1. Çekirdek: keşif, ayrıştırma, bulgu modeli, CLI iskeleti
2. Güvenlik: kural motoru, XSS / yürütme / URL / `postMessage` kuralları, gizli anahtar tarama, SARIF
3. Veri akışı: kaynak–sink–temizleyici modeli, taint analizi
4. Bağımlılıklar: `package-lock.json` ayrıştırma, OSV, çevrimdışı önbellek
5. Raporlama: tek dosyalık HTML rapor, Markdown
6. Yayın: CI, sürüm süreci, kıyaslamalar, dokümantasyon

## Lisans

MIT
