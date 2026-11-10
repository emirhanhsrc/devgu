# Yol haritası

Sıralama, kullanıcıya sağlanan değere ve doğrulanabilirliğe göre yapılır. Burada olmayan bir özellik "planlı" sayılmaz.

## Tamamlandı (0.1.0)

Çekirdek, güvenlik kuralları, gizli anahtar taraması, taint analizi, OSV bağımlılık denetimi, SARIF/HTML/Markdown raporları, CLI.

## Sıradaki

1. **Bağımlılıklar:** `yarn.lock`, `pnpm-lock.yaml`, monorepo içindeki iç içe kilit dosyaları, lisans bilgisi, yinelenen paket tespiti
2. **Taint analizi:** fonksiyon çağrıları arası (inter-procedural) akışlar; `fetch().then()` ve `await` ile gelen yanıtlar; dosyalar arası akışlar
3. **Mimari analizi:** import grafı, döngüsel bağımlılık (Tarjan SCC), kullanılmayan export adayları, karmaşıklık ölçümleri
4. **Kural kalitesi:** gerçek açık kaynak projelerde yanlış-pozitif ölçümü ve kural ayarı
5. **Kullanılabilirlik:** `devgu scan --baseline` (yalnızca yeni bulgular), GitHub Action sarmalayıcısı

## Araştırma

- Eklenti SDK'sı: yalıtılmış süreçte çalışan üçüncü taraf kurallar
- Masaüstü arayüzü (Tauri) ve tarama geçmişi karşılaştırması
- Çalışma zamanı profil verisiyle birleşik performans analizi

## Yapılmayacaklar

Yapay zekâ/LLM tabanlı analiz, bulut tarafı kod yükleme, otomatik kod düzeltme veya bağımlılık güncelleme.
