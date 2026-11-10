# Benchmarks

Bu değerler `npm run bench` ile üretilen **gerçek ölçümlerdir**; başka makinelerde farklı çıkar.
Sentetik depo: her dosya ~44 satır (40 fonksiyon + bir React bileşeni), her 10. dosyada kasıtlı bir XSS akışı,
her 25. dosyada sabit parola. Dosyalar 20 klasöre dağıtılır.

**Ortam:** Node v24.19.0, Intel Core i5-12400F (12 mantıksal çekirdek), Windows x64, tek iş parçacığı.

| Dosya |  Satır | Bulgu | Soğuk toplam | Ayrıştırma | Kurallar |  Heap | Sıcak toplam | Önbellek isabeti |
| ----: | -----: | ----: | -----------: | ---------: | -------: | ----: | -----------: | ---------------: |
|   200 |   8828 |    28 |       729 ms |      92 ms |   379 ms | 57 MB |       114 ms |          200/200 |
|  1000 |  44140 |   140 |      3080 ms |     254 ms |  1595 ms | 37 MB |       460 ms |        1000/1000 |
|  3000 | 132420 |   420 |      8932 ms |     714 ms |  4610 ms | 74 MB |      1302 ms |        3000/3000 |

- **Soğuk:** önbellek boş. **Sıcak:** hiçbir dosya değişmedi; her dosya içerik özetinden önbellekten okunur.
- "Toplam", ayrıştırma ve kural süresine ek olarak dosya okuma, SHA-256 ve önbellek yazmayı da içerir.
- Belleğin bellek ayak izi `process.memoryUsage().heapUsed` ile ölçülür; tepe değer değildir.

## Not edilen iyileştirme

11 güvenlik kuralının her biri başlangıçta dosya başına ayrı bir AST gezintisi yapıyordu (3000 dosyada kural süresi
13,2 sn). Ziyaretçiler tek geçişte birleştirilince 4,4 sn'ye indi; bulgu sayıları aynı kaldı
(`shared traversal` testi birleşik ve tek tek çalıştırmanın aynı sonucu verdiğini doğrular).

## Sınırlar

Gerçek projelerin dosya boyutu, JSX yoğunluğu ve bulgu yoğunluğu farklıdır. Bu tablo üretilen kod için bir ölçek
göstergesidir, gerçek dünya performans garantisi değildir. Tek çekirdek kullanıldığı için çok çekirdekli ölçekleme yoktur.
