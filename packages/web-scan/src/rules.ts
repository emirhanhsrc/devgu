import type { RuleMeta } from "@devgu/rule-engine";

type Def = Omit<RuleMeta, "targets" | "engine" | "version" | "references"> & {
  references?: string[];
};

function web(def: Def): RuleMeta {
  return { ...def, references: def.references ?? [], targets: "text", engine: "web", version: 1 };
}

const LIMIT_HEADER = {
  en: "Reads the response headers of the single URL that was requested. A header set only on other pages, or by a CDN for other paths, is not seen.",
  tr: "Yalnızca istenen tek URL'nin yanıt başlıklarını okur. Yalnızca başka sayfalarda ya da başka yollar için CDN tarafından eklenen başlıklar görülmez.",
};

/** Site-level (black-box) checks. Findings point at a URL instead of a file. */
export const WEB_RULES: RuleMeta[] = [
  web({
    id: "WEB-HDR-001",
    name: {
      en: "Missing Content-Security-Policy header",
      tr: "Content-Security-Policy başlığı yok",
    },
    description: {
      en: "The page is served without a Content-Security-Policy. A CSP limits where scripts can load from and is the main defence-in-depth layer against XSS.",
      tr: "Sayfa Content-Security-Policy olmadan sunuluyor. CSP, betiklerin nereden yüklenebileceğini sınırlar ve XSS'e karşı ana ek savunma katmanıdır.",
    },
    category: "web-headers",
    severity: "MEDIUM",
    confidence: "HIGH",
    remediation: {
      en: "Send a Content-Security-Policy header, starting with default-src 'self' and adding only the sources the site needs. Avoid 'unsafe-inline' and 'unsafe-eval'.",
      tr: "Content-Security-Policy başlığı gönderin; default-src 'self' ile başlayıp yalnızca sitenin gerçekten ihtiyaç duyduğu kaynakları ekleyin. 'unsafe-inline' ve 'unsafe-eval' kullanmayın.",
    },
    references: ["https://developer.mozilla.org/docs/Web/HTTP/CSP"],
    limitations: LIMIT_HEADER,
  }),
  web({
    id: "WEB-HDR-002",
    name: {
      en: "Missing Strict-Transport-Security header",
      tr: "Strict-Transport-Security başlığı yok",
    },
    description: {
      en: "An HTTPS page does not send HSTS, so a browser can still be downgraded to plain HTTP on the first or a later visit.",
      tr: "HTTPS sayfa HSTS göndermiyor; bu yüzden tarayıcı ilk veya sonraki ziyarette düz HTTP'ye düşürülebilir.",
    },
    category: "web-headers",
    severity: "LOW",
    confidence: "HIGH",
    remediation: {
      en: "Send Strict-Transport-Security: max-age=31536000; includeSubDomains once the whole site works over HTTPS.",
      tr: "Site tamamen HTTPS ile çalıştığında Strict-Transport-Security: max-age=31536000; includeSubDomains gönderin.",
    },
    references: ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"],
    limitations: LIMIT_HEADER,
  }),
  web({
    id: "WEB-HDR-003",
    name: { en: "Missing X-Content-Type-Options header", tr: "X-Content-Type-Options başlığı yok" },
    description: {
      en: "Without X-Content-Type-Options: nosniff a browser may guess a different content type than the server declared.",
      tr: "X-Content-Type-Options: nosniff olmadan tarayıcı, sunucunun bildirdiğinden farklı bir içerik türü tahmin edebilir.",
    },
    category: "web-headers",
    severity: "LOW",
    confidence: "HIGH",
    remediation: {
      en: "Send X-Content-Type-Options: nosniff.",
      tr: "X-Content-Type-Options: nosniff gönderin.",
    },
    references: ["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options"],
    limitations: LIMIT_HEADER,
  }),
  web({
    id: "WEB-HDR-004",
    name: { en: "No clickjacking protection", tr: "Clickjacking koruması yok" },
    description: {
      en: "The page sets neither X-Frame-Options nor a CSP frame-ancestors directive, so any site can embed it in a frame.",
      tr: "Sayfa ne X-Frame-Options ne de CSP frame-ancestors yönergesi ayarlıyor; her site onu bir çerçeve içine gömebilir.",
    },
    category: "web-headers",
    severity: "LOW",
    confidence: "HIGH",
    remediation: {
      en: "Send Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: SAMEORIGIN).",
      tr: "Content-Security-Policy: frame-ancestors 'self' (ya da X-Frame-Options: SAMEORIGIN) gönderin.",
    },
    references: ["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options"],
    limitations: LIMIT_HEADER,
  }),
  web({
    id: "WEB-HDR-005",
    name: {
      en: "Server technology disclosed in headers",
      tr: "Başlıklarda sunucu teknolojisi açığa çıkıyor",
    },
    description: {
      en: "The Server or X-Powered-By header names the software (and often its version), which helps an attacker pick known exploits.",
      tr: "Server veya X-Powered-By başlığı yazılımı (çoğu zaman sürümüyle) ele veriyor; bu da saldırganın bilinen açıkları seçmesini kolaylaştırır.",
    },
    category: "web-headers",
    severity: "INFO",
    confidence: "HIGH",
    remediation: {
      en: "Remove X-Powered-By and strip version numbers from the Server header.",
      tr: "X-Powered-By başlığını kaldırın ve Server başlığındaki sürüm numaralarını gizleyin.",
    },
    limitations: LIMIT_HEADER,
  }),
  web({
    id: "WEB-MAP-001",
    name: { en: "Source map publicly accessible", tr: "Kaynak haritası (source map) herkese açık" },
    description: {
      en: "A JavaScript source map is downloadable. It lets anyone reconstruct your original, unminified source code (names, comments, internal routes, sometimes keys).",
      tr: "Bir JavaScript kaynak haritası indirilebiliyor. Bu, herkesin özgün ve küçültülmemiş kaynak kodunuzu (adlar, yorumlar, iç yollar, bazen anahtarlar) yeniden oluşturmasına izin verir.",
    },
    category: "web-exposure",
    severity: "MEDIUM",
    confidence: "HIGH",
    remediation: {
      en: "Do not deploy .map files to production (or serve them only to authenticated developers) and remove the sourceMappingURL comment from public bundles.",
      tr: "Üretim ortamına .map dosyalarını yüklemeyin (ya da yalnızca oturum açmış geliştiricilere sunun) ve herkese açık paketlerden sourceMappingURL yorumunu kaldırın.",
    },
    limitations: {
      en: "Reports that a map exists and how many source files it embeds. DEVGU scanned the recovered sources with the normal rules, so other findings may come from them.",
      tr: "Haritanın var olduğunu ve kaç kaynak dosyası içerdiğini bildirir. DEVGU kurtarılan kaynakları normal kurallarla taradı; diğer bulgular bunlardan gelebilir.",
    },
  }),
  web({
    id: "WEB-EXP-001",
    name: {
      en: "Sensitive file exposed on the web server",
      tr: "Hassas dosya web sunucusunda açıkta",
    },
    description: {
      en: "A file that should never be public (.env, .git metadata) is downloadable. Environment files usually hold passwords and keys; .git lets anyone download the repository history.",
      tr: "Asla herkese açık olmaması gereken bir dosya (.env, .git üst verisi) indirilebiliyor. Ortam dosyaları genellikle parola ve anahtar içerir; .git ise depo geçmişinin indirilmesine izin verir.",
    },
    category: "web-exposure",
    severity: "HIGH",
    confidence: "HIGH",
    remediation: {
      en: "Block these paths in the web server, move the files out of the web root, and rotate every secret that was inside.",
      tr: "Bu yolları web sunucusunda engelleyin, dosyaları web kök dizininin dışına taşıyın ve içindeki tüm gizli bilgileri yenileyin.",
    },
    limitations: {
      en: "Only a few well-known paths are probed, and the content is checked to look like the real file so that a catch-all 200 page is not reported.",
      tr: "Yalnızca birkaç bilinen yol denenir ve her yanıtın gerçek dosyaya benzediği doğrulanır; böylece her yola 200 dönen sayfalar raporlanmaz.",
    },
  }),
  web({
    id: "WEB-MIX-001",
    name: {
      en: "Insecure resource loaded by an HTTPS page",
      tr: "HTTPS sayfa güvensiz bir kaynak yüklüyor",
    },
    description: {
      en: "An HTTPS page references a script, stylesheet or frame over plain http://. It can be tampered with in transit and browsers may block it.",
      tr: "HTTPS bir sayfa, düz http:// üzerinden bir betik, stil dosyası veya çerçeveye başvuruyor. Yolda değiştirilebilir ve tarayıcılar engelleyebilir.",
    },
    category: "web-transport",
    severity: "MEDIUM",
    confidence: "HIGH",
    remediation: {
      en: "Load every resource over https:// (or use protocol-relative/absolute-path URLs).",
      tr: "Tüm kaynakları https:// üzerinden yükleyin (ya da mutlak yol kullanın).",
    },
    limitations: {
      en: "Only resources written in the initial HTML are checked, not those added later by scripts.",
      tr: "Yalnızca ilk HTML'de yazılı kaynaklar denetlenir; betiklerin sonradan eklediği kaynaklar denetlenmez.",
    },
  }),
];
