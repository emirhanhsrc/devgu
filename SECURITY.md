# Güvenlik politikası

DEVGU, güvenilmeyen depoları analiz eden bir güvenlik aracıdır. Bu yüzden DEVGU'nun kendisinin
sömürülebilir olmaması en önemli gereksinimdir. Tehdit modeli: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Açık bildirme

Bir güvenlik açığı bulduysan **herkese açık issue açma**. Bunun yerine GitHub'ın özel bildirimini kullan:
depodaki **Security → Report a vulnerability** sayfası.

Bildirimde şunlar işe yarar:

- Etkilenen sürüm (`devgu version`) ve ortam
- Açığı yeniden üreten en küçük depo veya dosya
- Etki: kod çalıştırma, depo dışı dosya okuma/yazma, gizli anahtar sızıntısı, rapor üzerinden betik çalıştırma, hizmet reddi

Bildirimleri en kısa sürede değerlendirmeye çalışırız; düzeltme yayınlanana kadar ayrıntıyı gizli tutmanı rica ederiz.

## Kapsam

Kapsam içinde:

- Taranan bir depo aracılığıyla DEVGU sürecinde kod çalıştırma veya depo dışı dosyaya erişim
- Sembolik bağlantı / yol aşımı ile sınır atlatma
- ReDoS veya kaynak tüketimiyle hizmet reddi
- HTML/Markdown/SARIF/terminal raporlarında enjeksiyon (XSS, escape dizisi)
- Gizli anahtarların çıktıda, günlükte veya önbellekte açık görünmesi
- `--online` dışında ağ erişimi

Kapsam dışında: bir kuralın zafiyeti kaçırması veya yanlış pozitif üretmesi. Bunlar için normal issue aç
("Yanlış pozitif / kaçan bulgu" şablonu); kurallar bilinçli olarak sınırlıdır ve her birinin `limitations` alanı vardır.

## Desteklenen sürümler

Yalnızca en son yayınlanan sürüm düzeltme alır.

## Sınırlar

DEVGU bir statik analiz aracıdır. Bir bulgu bulunmaması kodun güvenli olduğunu kanıtlamaz; frontend analizi
sunucu tarafı yetkilendirmesi hakkında bir şey söyleyemez.
