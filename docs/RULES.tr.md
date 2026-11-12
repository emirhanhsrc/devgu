# DEVGU kural kataloğu

`npm run docs:rules` ile üretilir. Elle düzenlemeyin. Her kural, neyi tespit edemeyeceğini listeler.

| Kural                                 | Şiddet   | Güven  | Motor        | Ad                                                                 |
| ------------------------------------- | -------- | ------ | ------------ | ------------------------------------------------------------------ |
| [DEP-VULN-001](#dep-vuln-001)         | HIGH     | HIGH   | dependencies | Bilinen bir zafiyete sahip bağımlılık                              |
| [JS-CFG-001](#js-cfg-001)             | LOW      | MEDIUM | security     | Güvensiz http:// uç noktası                                        |
| [JS-CFG-002](#js-cfg-002)             | MEDIUM   | MEDIUM | security     | Herkese açık ön uç ortam değişkeninde sır görünümlü değer          |
| [JS-EXEC-001](#js-exec-001)           | HIGH     | MEDIUM | security     | Dinamik kod yürütme (eval / Function yapıcısı)                     |
| [JS-EXEC-002](#js-exec-002)           | MEDIUM   | HIGH   | security     | setTimeout/setInterval'e dizge veriliyor                           |
| [JS-MSG-001](#js-msg-001)             | MEDIUM   | MEDIUM | security     | Joker (*) hedef origin ile postMessage                             |
| [JS-MSG-002](#js-msg-002)             | MEDIUM   | MEDIUM | security     | origin denetimi olmayan message olay işleyicisi                    |
| [JS-STORE-001](#js-store-001)         | LOW      | LOW    | security     | Web depolamasında veya çerezlerde hassas görünen veri              |
| [JS-TAINT-001](#js-taint-001)         | HIGH     | HIGH   | taint        | DOM tabanlı XSS: güvenilmez veri bir HTML hedefine ulaşıyor        |
| [JS-TAINT-002](#js-taint-002)         | CRITICAL | HIGH   | taint        | Kod enjeksiyonu: güvenilmez veri bir kod yürütme hedefine ulaşıyor |
| [JS-TAINT-003](#js-taint-003)         | MEDIUM   | HIGH   | taint        | Güvenilmez veri bir gezinme veya bağlantı hedefine ulaşıyor        |
| [JS-URL-001](#js-url-001)             | MEDIUM   | HIGH   | security     | javascript: URL'si                                                 |
| [JS-XSS-001](#js-xss-001)             | MEDIUM   | LOW    | security     | innerHTML/outerHTML'e dinamik değer atanıyor                       |
| [JS-XSS-002](#js-xss-002)             | MEDIUM   | LOW    | security     | Dinamik işaretleme ile React dangerouslySetInnerHTML               |
| [JS-XSS-003](#js-xss-003)             | MEDIUM   | LOW    | security     | insertAdjacentHTML veya document.write'a dinamik HTML veriliyor    |
| [SEC-AWS-001](#sec-aws-001)           | HIGH     | HIGH   | secrets      | AWS erişim anahtarı kimliği                                        |
| [SEC-AWS-002](#sec-aws-002)           | CRITICAL | HIGH   | secrets      | AWS gizli erişim anahtarı                                          |
| [SEC-CONNSTR-001](#sec-connstr-001)   | HIGH     | HIGH   | secrets      | Bağlantı dizgesinde kimlik bilgileri                               |
| [SEC-GITHUB-001](#sec-github-001)     | CRITICAL | HIGH   | secrets      | GitHub token'ı                                                     |
| [SEC-GOOGLE-001](#sec-google-001)     | MEDIUM   | HIGH   | secrets      | Google API anahtarı                                                |
| [SEC-JWT-001](#sec-jwt-001)           | MEDIUM   | MEDIUM | secrets      | JSON Web Token                                                     |
| [SEC-PASSWORD-001](#sec-password-001) | HIGH     | MEDIUM | secrets      | Koda gömülü parola                                                 |
| [SEC-PRIVKEY-001](#sec-privkey-001)   | CRITICAL | HIGH   | secrets      | Özel anahtar                                                       |
| [SEC-SLACK-001](#sec-slack-001)       | HIGH     | HIGH   | secrets      | Slack token'ı                                                      |
| [SEC-STRIPE-001](#sec-stripe-001)     | CRITICAL | HIGH   | secrets      | Stripe canlı anahtarı                                              |
| [SEC-TOKEN-001](#sec-token-001)       | HIGH     | MEDIUM | secrets      | Koda gömülü API anahtarı veya token                                |

## DEP-VULN-001

**Bilinen bir zafiyete sahip bağımlılık**

Kilit dosyasındaki bir paket sürümü, OSV veritabanındaki bir danışma kaydıyla (GitHub Advisory Database, zararlı paket raporları, ...) eşleşiyor.

- Kategori: dependency-vulnerability
- Varsayılan şiddet: HIGH
- Varsayılan güven: HIGH

**Çözüm:** Düzeltilmiş bir sürüme yükseltin (bulguya bakın) ya da bağımlılığı kaldırın. `npm audit fix` komutunu yeniden çalıştırın veya kilit dosyasını güncelleyip değişiklikleri gözden geçirin.

**Sınırlamalar:** Kök package-lock.json içindeki tam sürümleri danışma verileriyle eşleştirir; kodunuzun zafiyetli fonksiyonu çağırıp çağırmadığını bilemez. Şiddet, danışma kaydından (veya CVSS v3 vektöründen) gelir ve yoksa MEDIUM varsayılır. yarn.lock, pnpm-lock.yaml ve iç içe kilit dosyaları henüz analiz edilmez.

Kaynaklar:

- https://osv.dev/
- https://cwe.mitre.org/data/definitions/1395.html

## JS-CFG-001

**Güvensiz http:// uç noktası**

Koda gömülü bir http:// URL'si trafiği şifresiz gönderir ve ağ yolunda dinlenmeye veya değiştirilmeye olanak tanır.

- Kategori: configuration
- Varsayılan şiddet: LOW
- Varsayılan güven: MEDIUM

**Çözüm:** https:// kullanın (veya üretimde https olan protokol-göreli bir yapılandırma değeri).

**Sınırlamalar:** Loopback, .local/.test adresleri ve bilinen ad alanı URL'leri yok sayılır. URL'nin yalnızca geliştirmede kullanılıp kullanılmadığını anlayamaz.

Kaynaklar:

- https://cwe.mitre.org/data/definitions/319.html

## JS-CFG-002

**Herkese açık ön uç ortam değişkeninde sır görünümlü değer**

VITE_, REACT_APP_ veya NEXT_PUBLIC_ gibi önekli değişkenler, derleme sırasında tarayıcı paketine gömülür. Orada saklanan her şey her ziyaretçiye görünür.

- Kategori: configuration
- Varsayılan şiddet: MEDIUM
- Varsayılan güven: MEDIUM

**Çözüm:** Sırları sunucuda tutun ve ön uca yalnızca dar kapsamlı bir uç nokta açın.

**Sınırlamalar:** Değişken adına göre karar verir. Harita veya analitik anahtarları gibi herkese açık kimlikler meşru biçimde ifşa edilir; yalnızca KEY içeren adlar LOW raporlanır.

Kaynaklar:

- https://vite.dev/guide/env-and-mode#env-files
- https://cwe.mitre.org/data/definitions/540.html

## JS-EXEC-001

**Dinamik kod yürütme (eval / Function yapıcısı)**

eval() ve Function yapıcısı dizgeleri koda derler. Sabit olmayan girdiyle bu, keyfi kod yürütülmesine izin verir ve Content-Security-Policy sıkılaştırmasını etkisiz kılar.

- Kategori: code-execution
- Varsayılan şiddet: HIGH
- Varsayılan güven: MEDIUM

**Çözüm:** Dinamik değerlendirmeyi kaldırın. Veri için JSON.parse, yönlendirme için arama tabloları veya gerçek bir ayrıştırıcı kullanın.

**Sınırlamalar:** API kullanımını raporlar, kanıtlanmış bir istismarı değil. Yalnızca sabit dizgelerle yapılan çağrı LOW raporlanır. `const e = eval` gibi takma adlı çağrılar izlenmez.

Kaynaklar:

- https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_direct_eval!
- https://cwe.mitre.org/data/definitions/95.html

## JS-EXEC-002

**setTimeout/setInterval'e dizge veriliyor**

Bir zamanlayıcıya fonksiyon yerine dizge vermek, tarayıcının onu eval() gibi değerlendirmesine yol açar. Katı Content-Security-Policy'yi bozar ve bir kod enjeksiyonu hedefidir.

- Kategori: code-execution
- Varsayılan şiddet: MEDIUM
- Varsayılan güven: HIGH

**Çözüm:** Fonksiyon geçirin: setTimeout(() => doWork(value), delay).

**Sınırlamalar:** Yalnızca dizge sabitlerini, şablonları ve dizge birleştirmelerini algılar; değişkende tutulan dizgeler görülmez.

Kaynaklar:

- https://developer.mozilla.org/docs/Web/API/setTimeout#the_this_problem
- https://cwe.mitre.org/data/definitions/95.html

## JS-MSG-001

**Joker (\*) hedef origin ile postMessage**

window.postMessage(data, "*") mesajı, hedef pencerede o an hangi origin varsa ona teslim eder. Hassas veriler bir saldırgan sayfası tarafından alınabilir.

- Kategori: postmessage
- Varsayılan şiddet: MEDIUM
- Varsayılan güven: MEDIUM

**Çözüm:** İkinci argüman olarak beklenen tam origin'i geçirin.

**Sınırlamalar:** Şiddet, gönderilen verinin ne kadar hassas olduğuna bağlıdır; bunu statik bir tarama değerlendiremez.

Kaynaklar:

- https://developer.mozilla.org/docs/Web/API/Window/postMessage#security_concerns
- https://cwe.mitre.org/data/definitions/345.html

## JS-MSG-002

**origin denetimi olmayan message olay işleyicisi**

Bir pencere 'message' dinleyicisi her origin'den mesaj alır. event.origin doğrulanmadan, bu pencereye erişebilen herhangi bir sayfa ona veri gönderebilir.

- Kategori: postmessage
- Varsayılan şiddet: MEDIUM
- Varsayılan güven: MEDIUM

**Çözüm:** event.data'yı kullanmadan önce event.origin'i bir izin listesiyle karşılaştırın.

**Sınırlamalar:** Aynı dosya içinde çözülemeyen işleyiciler (içe aktarılmış fonksiyonlar, başka modüllere satır içi atıflar) analiz edilmez. Bir yardımcı fonksiyonun yaptığı origin denetimleri tanınmaz.

Kaynaklar:

- https://developer.mozilla.org/docs/Web/API/Window/postMessage#security_concerns
- https://cwe.mitre.org/data/definitions/346.html

## JS-STORE-001

**Web depolamasında veya çerezlerde hassas görünen veri**

localStorage, sessionStorage veya betikle ayarlanan çerezlerde saklanan token, parola ve benzeri değerler sayfadaki her betik tarafından okunabilir; bu yüzden bir XSS açığı onları ifşa eder.

- Kategori: storage
- Varsayılan şiddet: LOW
- Varsayılan güven: LOW

**Çözüm:** Oturum kimlik bilgileri için sunucunun ayarladığı HttpOnly, Secure, SameSite çerezleri tercih edin. Kimlik bilgilerini asla koda gömmeyin.

**Sınırlamalar:** Yalnızca anahtar adından karar verir. Bir token'ı localStorage'da saklamak her zaman bir zafiyet değil, bir ödünleşmedir; bu nedenle dinamik değerler LOW güvenle raporlanır.

Kaynaklar:

- https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage
- https://cwe.mitre.org/data/definitions/922.html

## JS-TAINT-001

**DOM tabanlı XSS: güvenilmez veri bir HTML hedefine ulaşıyor**

Saldırgan denetimindeki bir kaynaktan (URL, window.name, postMessage, girdi alanı) gelen veri, HTML için temizleyici olmadan innerHTML, document.write veya dangerouslySetInnerHTML gibi HTML ayrıştıran bir hedefe akıyor.

- Kategori: xss
- Varsayılan şiddet: HIGH
- Varsayılan güven: HIGH

**Çözüm:** Güvenilmez veriyi HTML olarak eklemeyin. textContent / React metin düğümleri kullanın ya da hedeften hemen önce DOMPurify ile temizleyin.

**Sınırlamalar:** Prosedür içi (intra-procedural): yalnızca tek dosya içindeki akışlar izlenir; atamalar, yapı bozma, dizge işlemleri ve küçük bir bilinen kaynak/temizleyici kümesi üzerinden. Fonksiyonlardan dönen, argüman olarak geçirilen, ağ üzerinden getirilen veya özel doğrulamayla korunan değerler izlenmez; bu yüzden eksik bir bulgu güvenliği kanıtlamaz.

Kaynaklar:

- https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/79.html

## JS-TAINT-002

**Kod enjeksiyonu: güvenilmez veri bir kod yürütme hedefine ulaşıyor**

Saldırgan denetimindeki bir kaynaktan gelen veri eval(), Function yapıcısı veya dizge tabanlı bir zamanlayıcıya akıyor; bu, keyfi betik yürütülmesine olanak tanır.

- Kategori: code-execution
- Varsayılan şiddet: CRITICAL
- Varsayılan güven: HIGH

**Çözüm:** Güvenilmez dizgeleri asla değerlendirmeyin. Veriyi JSON.parse ile ayrıştırın ve açık arama tablolarıyla yönlendirin.

**Sınırlamalar:** Prosedür içi (intra-procedural): yalnızca tek dosya içindeki akışlar izlenir; atamalar, yapı bozma, dizge işlemleri ve küçük bir bilinen kaynak/temizleyici kümesi üzerinden. Fonksiyonlardan dönen, argüman olarak geçirilen, ağ üzerinden getirilen veya özel doğrulamayla korunan değerler izlenmez; bu yüzden eksik bir bulgu güvenliği kanıtlamaz.

Kaynaklar:

- https://cwe.mitre.org/data/definitions/95.html

## JS-TAINT-003

**Güvenilmez veri bir gezinme veya bağlantı hedefine ulaşıyor**

Saldırgan denetimindeki bir kaynaktan gelen veri, bir bağlantı veya gezinme hedefini belirliyor. Bu, açık yönlendirmelere ve javascript: URL betik yürütülmesine olanak tanır.

- Kategori: url
- Varsayılan şiddet: MEDIUM
- Varsayılan güven: HIGH

**Çözüm:** Gezinmeden önce hedefi bir yol/origin izin listesiyle doğrulayın ve http(s) dışındaki her şemayı reddedin.

**Sınırlamalar:** Prosedür içi (intra-procedural): yalnızca tek dosya içindeki akışlar izlenir; atamalar, yapı bozma, dizge işlemleri ve küçük bir bilinen kaynak/temizleyici kümesi üzerinden. Fonksiyonlardan dönen, argüman olarak geçirilen, ağ üzerinden getirilen veya özel doğrulamayla korunan değerler izlenmez; bu yüzden eksik bir bulgu güvenliği kanıtlamaz. Hedefin çevresinde koşul olarak yazılan izin listesi denetimleri tanınmaz ve yanlış pozitiflere yol açabilir.

Kaynaklar:

- https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/601.html

## JS-URL-001

**javascript: URL'si**

javascript: URL'si takip edildiğinde kod çalıştırır. Bağlantılarda ve gezinme hedeflerinde kullanılır ve katı bir Content-Security-Policy tarafından engellenir.

- Kategori: url
- Varsayılan şiddet: MEDIUM
- Varsayılan güven: HIGH

**Çözüm:** javascript: URL'si yerine bir olay işleyici veya buton öğesi kullanın.

**Sınırlamalar:** Yalnızca bağlantı özniteliklerindeki, href/src atamalarındaki ve gezinme çağrılarındaki sabit javascript: URL'leri raporlanır. Dinamik URL'ler JS-TAINT-003 kapsamındadır.

Kaynaklar:

- https://cwe.mitre.org/data/definitions/79.html
- https://developer.mozilla.org/docs/Web/URI/Reference/Schemes/javascript

## JS-XSS-001

**innerHTML/outerHTML'e dinamik değer atanıyor**

innerHTML veya outerHTML'e sabit olmayan bir değer atanıyor. Değerin herhangi bir parçası saldırgan denetimindeyse sayfa XSS'e açıktır. Bu kural yalnızca riskli API kullanımını işaret eder; kanıtlanmış güvenilmez kaynaktan gelen akışları JS-TAINT-001 raporlar.

- Kategori: xss
- Varsayılan şiddet: MEDIUM
- Varsayılan güven: LOW

**Çözüm:** Metin için textContent kullanın, düğümleri createElement ile oluşturun ya da işaretlemeyi atamadan önce DOMPurify gibi bakımlı bir temizleyiciyle temizleyin.

**Sınırlamalar:** Değerin nereden geldiğini bilmez, bu yüzden güven düzeyi LOW'dur. Sabit dizgeler ve bilinen temizleyicilerden geçen değerler yok sayılır; özel temizleyiciler tanınmaz.

Kaynaklar:

- https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/79.html

## JS-XSS-002

**Dinamik işaretleme ile React dangerouslySetInnerHTML**

dangerouslySetInnerHTML, React'in kaçışlamasını devre dışı bırakır. Saldırgan denetimindeki içerik barındıran dinamik işaretleme XSS'e yol açar.

- Kategori: xss
- Varsayılan şiddet: MEDIUM
- Varsayılan güven: LOW

**Çözüm:** İçeriği React öğeleri olarak render edin ya da geçmeden önce DOMPurify ile temizleyin.

**Sınırlamalar:** İşaretlemenin güvenilir olup olmadığını anlayamaz. Sabit dizgeler ve DOMPurify/sanitize-html çağrıları yok sayılır; başka yerde temizlenmiş bir değişken yine de raporlanır.

Kaynaklar:

- https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html
- https://cwe.mitre.org/data/definitions/79.html

## JS-XSS-003

**insertAdjacentHTML veya document.write'a dinamik HTML veriliyor**

insertAdjacentHTML, document.write ve document.writeln argümanını HTML olarak ayrıştırır. Dinamik bir argüman saldırgan denetimindeki işaretlemeyi sokabilir.

- Kategori: xss
- Varsayılan şiddet: MEDIUM
- Varsayılan güven: LOW

**Çözüm:** Metni textContent/insertAdjacentText ile ekleyin ya da işaretlemeyi önce temizleyin.

**Sınırlamalar:** Argümanın kaynağını bilmez. Sabit dizgeler ve tanınan temizleyici çağrıları yok sayılır.

Kaynaklar:

- https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/79.html

## SEC-AWS-001

**AWS erişim anahtarı kimliği**

Kaynakta bir AWS erişim anahtarı tanımlayıcısı bulunuyor.

- Kategori: secrets
- Varsayılan şiddet: HIGH
- Varsayılan güven: HIGH

**Çözüm:** Kimlik bilgisini iptal edip döndürün (rotate), koddan ve git geçmişinden kaldırın ve çalışma zamanında bir sır yöneticisinden veya ortamdan yükleyin.

**Sınırlamalar:** Desenle tespit edildi. Değer iptal edilmiş, test amaçlı veya örnek bir kimlik bilgisi olabilir; tarayıcı hâlâ geçerli olup olmadığını denetleyemez.

Kaynaklar:

- https://cwe.mitre.org/data/definitions/798.html

## SEC-AWS-002

**AWS gizli erişim anahtarı**

Kaynakta bir AWS gizli erişim anahtarı atanıyor.

- Kategori: secrets
- Varsayılan şiddet: CRITICAL
- Varsayılan güven: HIGH

**Çözüm:** Kimlik bilgisini iptal edip döndürün (rotate), koddan ve git geçmişinden kaldırın ve çalışma zamanında bir sır yöneticisinden veya ortamdan yükleyin.

**Sınırlamalar:** Desenle tespit edildi. Değer iptal edilmiş, test amaçlı veya örnek bir kimlik bilgisi olabilir; tarayıcı hâlâ geçerli olup olmadığını denetleyemez.

Kaynaklar:

- https://cwe.mitre.org/data/definitions/798.html

## SEC-CONNSTR-001

**Bağlantı dizgesinde kimlik bilgileri**

Bir veritabanı veya aracı (broker) bağlantı dizgesi satır içi parola içeriyor.

- Kategori: secrets
- Varsayılan şiddet: HIGH
- Varsayılan güven: HIGH

**Çözüm:** Kimlik bilgisini iptal edip döndürün (rotate), koddan ve git geçmişinden kaldırın ve çalışma zamanında bir sır yöneticisinden veya ortamdan yükleyin.

**Sınırlamalar:** Desenle tespit edildi. Değer iptal edilmiş, test amaçlı veya örnek bir kimlik bilgisi olabilir; tarayıcı hâlâ geçerli olup olmadığını denetleyemez.

Kaynaklar:

- https://cwe.mitre.org/data/definitions/798.html

## SEC-GITHUB-001

**GitHub token'ı**

Kaynakta bir GitHub kişisel erişim, OAuth veya uygulama token'ı bulunuyor.

- Kategori: secrets
- Varsayılan şiddet: CRITICAL
- Varsayılan güven: HIGH

**Çözüm:** Kimlik bilgisini iptal edip döndürün (rotate), koddan ve git geçmişinden kaldırın ve çalışma zamanında bir sır yöneticisinden veya ortamdan yükleyin.

**Sınırlamalar:** Desenle tespit edildi. Değer iptal edilmiş, test amaçlı veya örnek bir kimlik bilgisi olabilir; tarayıcı hâlâ geçerli olup olmadığını denetleyemez.

Kaynaklar:

- https://cwe.mitre.org/data/definitions/798.html

## SEC-GOOGLE-001

**Google API anahtarı**

Kaynakta bir Google API anahtarı bulunuyor.

- Kategori: secrets
- Varsayılan şiddet: MEDIUM
- Varsayılan güven: HIGH

**Çözüm:** Kimlik bilgisini iptal edip döndürün (rotate), koddan ve git geçmişinden kaldırın ve çalışma zamanında bir sır yöneticisinden veya ortamdan yükleyin. Anahtarı Google Cloud konsolunda HTTP yönlendiricisine veya API'ye göre kısıtlayın.

**Sınırlamalar:** Desenle tespit edildi. Değer iptal edilmiş, test amaçlı veya örnek bir kimlik bilgisi olabilir; tarayıcı hâlâ geçerli olup olmadığını denetleyemez. Tarayıcı anahtarları, düzgün kısıtlandığında herkese açık olacak şekilde tasarlanmıştır.

Kaynaklar:

- https://cwe.mitre.org/data/definitions/798.html

## SEC-JWT-001

**JSON Web Token**

JWT benzeri bir token koda gömülü. Token'lar kimlik taşıyabilir ve süreleri dolana dek erişim sağlayabilir.

- Kategori: secrets
- Varsayılan şiddet: MEDIUM
- Varsayılan güven: MEDIUM

**Çözüm:** Kimlik bilgisini iptal edip döndürün (rotate), koddan ve git geçmişinden kaldırın ve çalışma zamanında bir sır yöneticisinden veya ortamdan yükleyin.

**Sınırlamalar:** Desenle tespit edildi. Değer iptal edilmiş, test amaçlı veya örnek bir kimlik bilgisi olabilir; tarayıcı hâlâ geçerli olup olmadığını denetleyemez. Token'ın süresi çoktan dolmuş olabilir.

Kaynaklar:

- https://cwe.mitre.org/data/definitions/798.html

## SEC-PASSWORD-001

**Koda gömülü parola**

Gerçek bir parola gibi görünen bir dizge sabiti, parola benzeri bir ada atanıyor.

- Kategori: secrets
- Varsayılan şiddet: HIGH
- Varsayılan güven: MEDIUM

**Çözüm:** Kimlik bilgisini iptal edip döndürün (rotate), koddan ve git geçmişinden kaldırın ve çalışma zamanında bir sır yöneticisinden veya ortamdan yükleyin.

**Sınırlamalar:** Sezgisel: etiket, yer tutucu veya düz sözcük gibi görünen değerler atlanır; bu yüzden zayıf gerçek parolalar kaçırılabilir.

Kaynaklar:

- https://cwe.mitre.org/data/definitions/798.html

## SEC-PRIVKEY-001

**Özel anahtar**

Burada PEM kodlu bir özel anahtar bloğu başlıyor.

- Kategori: secrets
- Varsayılan şiddet: CRITICAL
- Varsayılan güven: HIGH

**Çözüm:** Kimlik bilgisini iptal edip döndürün (rotate), koddan ve git geçmişinden kaldırın ve çalışma zamanında bir sır yöneticisinden veya ortamdan yükleyin.

**Sınırlamalar:** Yalnızca başlık eşleşir; dosya bilerek herkese açık bir test anahtarı içerebilir.

Kaynaklar:

- https://cwe.mitre.org/data/definitions/798.html

## SEC-SLACK-001

**Slack token'ı**

Kaynakta bir Slack API token'ı bulunuyor.

- Kategori: secrets
- Varsayılan şiddet: HIGH
- Varsayılan güven: HIGH

**Çözüm:** Kimlik bilgisini iptal edip döndürün (rotate), koddan ve git geçmişinden kaldırın ve çalışma zamanında bir sır yöneticisinden veya ortamdan yükleyin.

**Sınırlamalar:** Desenle tespit edildi. Değer iptal edilmiş, test amaçlı veya örnek bir kimlik bilgisi olabilir; tarayıcı hâlâ geçerli olup olmadığını denetleyemez.

Kaynaklar:

- https://cwe.mitre.org/data/definitions/798.html

## SEC-STRIPE-001

**Stripe canlı anahtarı**

Kaynakta bir Stripe canlı gizli veya kısıtlı anahtarı bulunuyor.

- Kategori: secrets
- Varsayılan şiddet: CRITICAL
- Varsayılan güven: HIGH

**Çözüm:** Kimlik bilgisini iptal edip döndürün (rotate), koddan ve git geçmişinden kaldırın ve çalışma zamanında bir sır yöneticisinden veya ortamdan yükleyin.

**Sınırlamalar:** Desenle tespit edildi. Değer iptal edilmiş, test amaçlı veya örnek bir kimlik bilgisi olabilir; tarayıcı hâlâ geçerli olup olmadığını denetleyemez.

Kaynaklar:

- https://cwe.mitre.org/data/definitions/798.html

## SEC-TOKEN-001

**Koda gömülü API anahtarı veya token**

Yüksek entropili bir dizge sabiti apiKey, secret veya token gibi bir ada atanıyor.

- Kategori: secrets
- Varsayılan şiddet: HIGH
- Varsayılan güven: MEDIUM

**Çözüm:** Kimlik bilgisini iptal edip döndürün (rotate), koddan ve git geçmişinden kaldırın ve çalışma zamanında bir sır yöneticisinden veya ortamdan yükleyin.

**Sınırlamalar:** Entropi tabanlı: rastgele görünen tanımlayıcılar (hash'ler, kimlikler) raporlanabilir ve düşük entropili gerçek sırlar kaçırılır.

Kaynaklar:

- https://cwe.mitre.org/data/definitions/798.html
