# Katkı rehberi

Katkıların için teşekkürler. DEVGU'nun üç değişmez ilkesi var; her değişiklik bunlara uymalı:

1. **Yapay zekâ yok.** Her bulgu açık bir kuraldan, bir algoritmadan veya güvenilir bir zafiyet veritabanından gelir.
2. **Sahte işlevsellik yok.** Tamamlanmamış özellik "experimental" olarak işaretlenir; sahte sayı veya buton eklenmez.
3. **Taranan kod güvenilmezdir.** Taranan hiçbir şey çalıştırılmaz, her girdi sınırlandırılır ve doğrulanır.

## Geliştirme ortamı

Gereksinimler: Node.js 20+ ve npm.

```bash
npm ci
npm run check      # build + lint + test
npm test           # yalnızca testler
npm run format     # Prettier
node apps/cli/dist/index.js scan fixtures/vulnerable
```

Paket sınırları [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) içinde. Analiz mantığı CLI'a değil, ilgili pakete yazılır.

## Commit mesajları

Conventional Commits biçimi: `feat(taint-analysis): ...`, `fix(core): ...`, `docs: ...`, `test: ...`,
`perf: ...`, `chore: ...`. Mesajlara yapay zekâ/araç imzası eklenmez.

## Yeni kural eklemek

Kural bir `Rule` nesnesidir (`packages/rule-engine/src/rules/` veya ilgili motor paketi). Bir kural şunları içermeli:

- Benzersiz `id`, `name`, `description`, `category`, `severity`, `confidence`
- `remediation` ve en az bir `references`
- **`limitations`**: kuralın neyi kanıtlayamadığı ve nerede yanılabileceği (zorunlu, dürüst olmalı)

Testler zorunludur:

1. Pozitif durum (kural bulgu üretiyor)
2. Negatif durum (kural sessiz kalıyor)
3. Yanlış-pozitif durumu: tehlikeli görünen ama güvenli kod
4. Uç durumlar (gölgeleme, TypeScript, JSX, bozuk girdi)

`fixtures/vulnerable` içindeki bir satıra `// expect: RULE-ID` ekle ve güvenli örneği `fixtures/safe` içine koy;
golden test ikisini birlikte doğrular. Kural eklendikten sonra `npm run docs:rules` ile `docs/RULES.md` güncellenir.

AST kurallarında `astRule` yardımcısını kullan: ziyaretçiler tek bir gezintide birleştirilir, bu yüzden kural içinde
kendi `traverse` çağrını yapma.

## Güvenlik hassasiyeti olan değişiklikler

Dosya sistemi, ağ, önbellek, rapor üretimi veya düzenli ifade eklerken [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
dosyasını oku. Yeni düzenli ifadeler doğrusal zamanlı olmalı (iç içe niceleyici yok) ve uzun satırlarla test edilmeli.
Rapor çıktılarına giren her depo kaynaklı metin ilgili biçim için kaçışlanmalı veya `textContent` ile yazılmalıdır.

## Pull request

`npm run check` geçmeli; PR şablonundaki kontrol listesini doldur. Davranış değişikliklerini `CHANGELOG.md` içine yaz.
