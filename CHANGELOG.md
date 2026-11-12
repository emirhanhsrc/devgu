# Changelog

Biçim [Keep a Changelog](https://keepachangelog.com/) ilkelerini, sürümleme [Semantic Versioning](https://semver.org/) ilkelerini izler.

## [Unreleased]

### Added

- Çok dilli çıktı (Türkçe / İngilizce): `--lang tr|en` bayrağı ve `devgu.config.json` içindeki `"lang"` alanı.
  Bulgu başlıkları/açıklamaları/çözümleri/sınırlamaları, taint veri akışı adımları, bağımlılık bulguları,
  metin / Markdown / HTML rapor etiketleri ve CLI iletileri yerelleştirildi. Dil tarama anında sabitlenir ve
  `meta.lang` alanıyla çıktıya yazılır. Kural kataloğu her iki dilde üretilir (`docs/RULES.md`, `docs/RULES.tr.md`).

## [0.1.0]

İlk sürüm adayı.

### Added

- Güvenli depo keşfi: sembolik bağlantılar izlenmez, boyut/dosya sayısı/satır uzunluğu sınırları, özel dışlamalar
- Babel ile JS / TS / JSX / TSX ayrıştırma; bozuk dosyalar taramayı durdurmaz
- Güvenlik kuralları: XSS (`innerHTML`, `dangerouslySetInnerHTML`, `insertAdjacentHTML`, `document.write`),
  `eval`/`Function`/string zamanlayıcılar, `javascript:` URL, `postMessage` (joker origin, origin kontrolsüz dinleyici),
  web depolamada hassas veri, `http://` uç noktalar, genel frontend ortam değişkenlerinde gizli değer
- Gizli anahtar taraması: sağlayıcı desenleri, parola/token sezgileri, entropi, maskeleme ve parmak izi
- Intra-procedural taint analizi (JS-TAINT-001/002/003): kaynak → sink veri akışı yolu, temizleyiciler, güven seviyesi
- Bağımlılık güvenliği: `package-lock.json` (v1/v2/v3), OSV entegrasyonu (varsayılan kapalı, `--online`), CVSS v3 hesabı, çevrimdışı önbellek
- Raporlar: metin, JSON, SARIF 2.1.0, Markdown ve CSP korumalı tek dosyalık HTML
- Gerekçeli bastırma (satır içi ve yapılandırma ile), içerik özetli artımlı önbellek
- CLI: `scan`, `rules list|explain`, `config init`, `cache clear`, `version`; anlamlı çıkış kodları
- Tek dosyalık dağıtım paketi (`npm run bundle`)

### Known limitations

- Taint analizi tek dosya ve tek fonksiyon zinciriyle sınırlı; fonksiyon çağrıları, dosyalar arası akışlar ve
  `fetch` yanıtları izlenmez
- Yalnızca kök `package-lock.json` analiz edilir; `yarn.lock` ve `pnpm-lock.yaml` henüz desteklenmez
- Mimari analizi (döngüsel bağımlılık, import grafı), masaüstü uygulaması ve eklenti SDK'sı bu sürümde yok
