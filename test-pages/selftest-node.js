// Headless half of the download-ad neutralizer self-test.
//
//   node test-pages/selftest-node.js
//
// Runs every assertion that does not need a DOM, directly against the real
// source files. Exit code 0 = shippable. The DOM-dependent assertions (the
// ad-slot selector against live markup, button-shape gating, label
// extraction) live in test-pages/neutralizer-selftest.html: open that file in
// Chrome and confirm the title reads PASS.
//
// These are not documentation. They are the enforcement mechanism for the
// false-positive guarantee: if Spanish prose starts matching the download
// vocabulary, or a legitimate release mirror lands on the conviction list,
// this exits non-zero.

const fs = require("fs");
const vm = require("vm");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const FILES = [
  "data/ad-networks.js",
  "data/allowlist.js",
  "data/typo-targets.js",
  "data/scam-phrases.js",
  "data/strings.js",
  "content/detector.js"
];

const ASSERTIONS = `
let __fails = 0;
function check(name, actual, expected, detail) {
  if (actual !== expected) {
    __fails++;
    console.log("FAIL: " + name + " -> expected " + expected + ", got " + actual +
      (detail ? " (" + detail + ")" : ""));
  }
}

// 1. Download vocabulary must not match ordinary prose. Without the /u flag,
// JavaScript treats an accented letter as a non-word character, so every
// Spanish and Portuguese page would match.
[
  "se descargará automáticamente",
  "el archivo se descargará",
  "baixará automaticamente",
  "o arquivo será baixado automaticamente",
  "header", "uploaded", "reloaded", "downloadable"
].forEach((s) => check("no-match " + JSON.stringify(s), guardianIsDownloadLabel(s), false));

[
  "Download", "DOWNLOAD NOW", "Free Download", "Descargar",
  "Télécharger", "Herunterladen", "Baixar", "下载", "ダウンロード", "다운로드"
].forEach((s) => check("match " + JSON.stringify(s), guardianIsDownloadLabel(s), true));

// 2. Legitimate download hosts: never convictable, always exempt.
const legit = [
  "download.documentfoundation.org", "download.mozilla.org",
  "objects.githubusercontent.com", "github.com", "fosshub.com",
  "gdlp01.c-wss.com", "download.ebz.epson.net", "apps.apple.com",
  "play.google.com", "mirrors.kernel.org", "sourceforge.net",
  "get.videolan.org", "nodejs.org", "rufus.ie"
];
legit.forEach((h) => check("not-decoy " + h, guardianHostOnList(h, GUARDIAN_DECOY_NETWORKS), false));
legit.forEach((h) => check("safe-host " + h, guardianHostOnList(h, GUARDIAN_DOWNLOAD_SAFE_HOSTS), true));

// Affiliate redirectors carry REAL vendor installers; mainstream ad networks
// carry honest advertisers. Neither may ever be conviction-grade.
[
  "go.skimresources.com", "anrdoezrs.net", "dpbolvw.net", "tkqlhce.com",
  "click.linksynergy.com", "awin1.com", "shareasale.com", "impact.com",
  "adclick.g.doubleclick.net", "securepubads.g.doubleclick.net",
  "taboola.com", "media.net", "outbrain.com", "criteo.com", "amazon-adsystem.com"
].forEach((h) => check("not-conviction " + h, guardianHostOnList(h, GUARDIAN_DECOY_NETWORKS), false));

["www.adsterra.com", "x.propellerads.com", "popads.net", "a.b.monetag.com"]
  .forEach((h) => check("is-decoy " + h, guardianHostOnList(h, GUARDIAN_DECOY_NETWORKS), true));

// 3. Documents and media are out of scope in code, not by scoring.
["a.pdf", "a.docx", "a.csv", "a.ics", "a.jpg", "a.mp3", "a.zip"].forEach((f) => {
  check("not-installer " + f, GUARDIAN_INSTALLER_RE.test("https://x/" + f), false);
  check("is-document " + f, GUARDIAN_DOCUMENT_RE.test("https://x/" + f), true);
});
["a.exe", "a.msi", "a.dmg", "a.apk", "a.pkg"].forEach((f) =>
  check("is-installer " + f, GUARDIAN_INSTALLER_RE.test("https://x/" + f), true));
check("installer with query", GUARDIAN_INSTALLER_RE.test("https://x/setup.exe?v=2"), true);

// 4. Click-tracker unwrapping: this is what lets a malware feed intersect an
// ad click-through at all.
const un = guardianUnwrapClick(
  "https://adclick.g.doubleclick.net/pcs/click?adurl=https%3A%2F%2Fevil.example%2Fsetup.exe");
check("unwrap nested", un.indexOf("https://evil.example/setup.exe") !== -1, true, un.join(" | "));
check("unwrap keeps literal", un.length >= 2, true);
check("plain unwrap len", guardianUnwrapClick("https://example.com/a").length, 1);
check("js href unwrap", guardianUnwrapClick("javascript:void(0)").length, 0);
check("mailto unwrap", guardianUnwrapClick("mailto:a@b.c").length, 0);
check("protocol-relative nested", guardianUnwrapClick(
  "https://t.example/c?url=%2F%2Fevil.example%2Fx.exe").some((u) => u.indexOf("evil.example") !== -1), true);

// 5. ccTLD-aware registrable labels. The same-party test rests on this.
check("ebay.co.uk", guardianRegistrableLabel("www.ebay.co.uk"), "ebay");
check("bbc vs example co.uk",
  guardianRegistrableLabel("bbc.co.uk") === guardianRegistrableLabel("example.co.uk"), false);
// gov.au is a SAME-PARTY suffix, not a typosquat one: the same-party test
// wants a wide list, the typosquat test wants a conservative one.
check("gov.au (same-party)", guardianSamePartyLabel("services.gov.au"), "services");

// 6. Multi-tenant hosts must be path-matched, never blocked wholesale.
// raw.githubusercontent.com alone is about a third of the URLhaus feed.
["raw.githubusercontent.com", "gist.githubusercontent.com",
 "objects.githubusercontent.com", "img1.wsimg.com", "bit.ly"].forEach((h) =>
  check("path-match " + h, guardianHostOnList(h, GUARDIAN_PATH_MATCH_HOSTS), true));
// Where the SUBDOMAIN is the tenant, hostname matching is already correct.
["evil.s3.amazonaws.com", "d1.cloudfront.net"].forEach((h) =>
  check("not-path-match " + h, guardianHostOnList(h, GUARDIAN_PATH_MATCH_HOSTS), false));

// The allowlist entry "github.com" does NOT cover raw.githubusercontent.com,
// which is precisely why that host needs path matching.
const allowCovers = GUARDIAN_ALLOWLIST.some(
  (d) => "raw.githubusercontent.com" === d || "raw.githubusercontent.com".endsWith("." + d));
check("allowlist does NOT cover raw.githubusercontent.com", allowCovers, false);

["google.com", "www.google.com", "amazon.com", "chase.com"].forEach((h) =>
  check("allowlisted stays safe " + h, guardianIsAllowlisted(h), true));

// 7. No substring class/id matching, anywhere. "ad" is the last two letters of
// "downlo-ad", so [class*="ad"] matches .download-button, #download and
// .downloads-wrap: the container of the REAL download.
check("ad-slot selector uses NO substring matching",
  GUARDIAN_AD_SLOT_SELECTOR.indexOf("*=") === -1, true, GUARDIAN_AD_SLOT_SELECTOR);
check("ad-slot selector uses NO suffix matching",
  GUARDIAN_AD_SLOT_SELECTOR.indexOf("$=") === -1, true);
check("ad-slot selector uses token matching for class",
  GUARDIAN_AD_SLOT_SELECTOR.indexOf('[class~="') !== -1, true);
GUARDIAN_AD_SLOT_SELECTOR.split(",").map((s) => s.trim())
  .filter((s) => s.indexOf("^=") !== -1)
  .forEach((s) => {
    const ok = ["google_ads_iframe_", "aswift_", "adfox_"]
      .some((stem) => s.indexOf(stem) !== -1);
    check("prefix selector is ad-specific: " + s, ok, true);
  });
["download-button", "downloads-wrap", "load-more", "upload", "breadcrumb",
 "admin", "adjacent", "headline"].forEach((w) =>
  check("collision word is not an ad slot token: " + w,
    GUARDIAN_AD_SLOT_SELECTOR.indexOf('"' + w + '"') === -1, true));

// 8. Typosquat coverage for popular names, including the variants edit
// distance alone cannot reach.
[
  ["wwwpaypal.com", "paypal"],     // the omitted dot after www
  ["wwwnetflix.com", "netflix"],
  ["paypa1.com", "paypal"],        // digit-for-letter look-alike
  ["faceb00k.com", "facebook"],
  ["amaz0n.com", "amazon"],
  ["micros0ft.com", "microsoft"],
  ["instagrarn.com", "instagram"], // rn -> m
  ["linkedln.com", "linkedin"],
  ["gooogle.com", "google"],       // doubled letter
  ["wikipedla.org", "wikipedia"]
].forEach(([host, want]) =>
  check("typosquat " + host + " -> " + want, guardianTyposquatOf(host), want));

// Real sites must stay clean.
["google.com", "www.bbc.co.uk", "wikipedia.org", "chase.com", "amazon.co.uk",
 "canvas.instructure.com", "wwwhatsnew.com", "microsoft.com"].forEach((h) =>
  check("not a typosquat: " + h, guardianTyposquatOf(h), null));

// The popular-name list is a TARGET list, never a trust list. If any of it
// leaked into the allowlist, those sites would stop being scanned entirely.
check("typo targets are not trusted",
  GUARDIAN_TYPO_TARGETS.some((t) => guardianIsAllowlisted(t + ".com")), false);
// The measured length floor. Dropping below 8 moves the false-positive rate.
check("every typo target is at least 8 characters",
  GUARDIAN_TYPO_TARGETS.every((t) => t.length >= 8), true,
  GUARDIAN_TYPO_TARGETS.filter((t) => t.length < 8).join(","));

// 9. The LINK check used by "Is this a scam?".
// It must accept only high-confidence look-alikes, because it is applied to
// every link on a page: a test that is wrong 0.4% of the time raises a false
// alarm on one page in four when a page has eighty links.
[
  ["paypa1.com", "paypal"],
  ["faceb00k.com", "facebook"],
  ["amaz0n.com", "amazon"],
  ["micros0ft.com", "microsoft"],
  ["paypal.com.evil.tk", "PayPal"] // brand mimic, not a typo
].forEach(([host, want]) =>
  check("link look-alike " + host, guardianLookalikeHost(host), want));

// These ARE edit-distance typosquat matches, and must NOT reach the link
// check. Each is a real, legitimate site.
["stripes.com", "lithub.com", "fetlife.com", "nltimes.nl", "cnsnews.com"]
  .forEach((h) => {
    check("link check ignores the edit-distance match: " + h,
      guardianLookalikeHost(h), null);
  });
["google.com", "wikipedia.org", "www.bbc.co.uk", "amazon.com"].forEach((h) =>
  check("link check clean: " + h, guardianLookalikeHost(h), null));

// 10. Real brand country registrations must never read as impostors.
// <brand>.com.<cc> is how a brand registers in a country; there are ~200 such
// registries and no hand-kept table can list them all, so this is judged by
// shape. Getting it wrong put a full-page "STOP. This is a scam." over a real
// bank.
["www.amazon.com.be", "amazon.com.be", "www.citibank.com.do", "walmart.com.gt",
 "ups.com.do", "correos.com.gt", "paypal.com.mx", "ebay.com.au"].forEach((h) =>
  check("real country registration is not a mimic: " + h,
    guardianLookalikeHost(h), null));

// ...while the attacker shapes stay caught: something after the ccTLD pair,
// or a throwaway TLD that exists mostly for abuse.
[["paypal.com.evil.net", "PayPal"], ["paypal.com.secure.tk", "PayPal"],
 ["roblox.com.ml", "Roblox"]].forEach(([h, want]) => {
  const m = guardianBrandMimic(h);
  check("brand mimic still caught: " + h, m && m.display, want);
});

// 11. A near-miss against the broad popular-site list must stay below the
// CAUTION threshold (4) on its own, not merely below the flag threshold (6).
[["www.coloradoan.com", true], ["www.coloradoan.com", false]].forEach(([h, cred]) => {
  const r = guardianAnalyze({
    title: "Local news", text: "Sign up for our newsletter", hostname: h,
    hasPasswordField: false, hasEmailInput: cred, insecureLogin: false, isEmail: false
  });
  check("broad-list near-miss stays quiet on " + h + " (login box: " + cred + ")",
    r.score < 4, true, "score " + r.score);
});

// ...but a real impostor with a login box still flags.
["paypa1.com", "faceb00k.com"].forEach((h) => {
  const r = guardianAnalyze({
    title: "Sign in", text: "Sign in to your account. Password required.",
    hostname: h, hasPasswordField: true, hasEmailInput: true,
    insecureLogin: false, isEmail: false
  });
  check("real impostor still flags: " + h, r.isScam, true, "score " + r.score);
});

// 12. The two label functions answer different questions and must stay apart.
// Widening the typosquat one made Kenya's nation.co.ke read as "nation", one
// letter from the allowlisted "notion", and warned on a national newspaper.
check("same-party label knows co.ke", guardianSamePartyLabel("www.nation.co.ke"), "nation");
check("registrable label does NOT (typosquat must not see it)",
  guardianRegistrableLabel("www.nation.co.ke"), "co");
check("nation.co.ke is not a typosquat", guardianTyposquatOf("www.nation.co.ke"), null);

// 13. Real brand country registrations must not be flagged by the
// brand-in-hostname path either. Guarding only the brand-mimic path left this
// open: citibank.com.do scored 6 and put "STOP. This is a scam." over a bank.
["citibank.com.do", "walmart.com.gt", "amazon.com.be", "ups.com.do",
 "paypal.com.mx", "amazon.com.au"].forEach((h) => {
  const r = guardianAnalyze({
    title: "", text: "", hostname: h, hasPasswordField: false,
    hasEmailInput: true, insecureLogin: false, isEmail: false
  });
  check("real country site scores 0: " + h, r.score, 0);
});

// ...and the planted-brand attacks still score.
[["secure-chase-login.com", "chase"], ["paypal.com.evil.net", "paypal"]]
  .forEach(([h]) => {
    const r = guardianAnalyze({
      title: "Sign in", text: "Sign in to your account", hostname: h,
      hasPasswordField: true, hasEmailInput: true, insecureLogin: false, isEmail: false
    });
    check("planted brand still flags: " + h, r.isScam, true, "score " + r.score);
  });

// The omitted-dot impostor must reach the flag threshold on a login page now
// that there is no document_start pass to catch it earlier.
["wwwpaypal.com", "paypa1.com"].forEach((h) => {
  const r = guardianAnalyze({
    title: "Sign in", text: "Sign in to your account", hostname: h,
    hasPasswordField: true, hasEmailInput: true, insecureLogin: false, isEmail: false
  });
  check("look-alike flags on a login page: " + h, r.isScam, true, "score " + r.score);
});

// 14. A high-confidence look-alike flags on the ADDRESS ALONE. The page
// behind one is usually a bare redirector with no form and no scam wording,
// which used to score 4 - a caution strip on a domain registered purely to
// impersonate a bank. Measured: zero of 12,000 real popular sites reach the
// warning threshold on a plain page.
["wwwpaypal.com", "paypa1.com", "faceb00k.com", "amaz0n.com", "micros0ft.com"]
  .forEach((h) => {
    const r = guardianAnalyze({
      title: "", text: "", hostname: h, hasPasswordField: false,
      hasEmailInput: false, insecureLogin: false, isEmail: false
    });
    check("look-alike flags with no form at all: " + h, r.isScam, true,
      "score " + r.score);
  });

// ...and an ordinary site with no form stays completely silent.
["google.com", "nytimes.com", "chase.com", "bbc.co.uk", "citibank.com.do",
 "stripes.com", "lithub.com"].forEach((h) => {
  const r = guardianAnalyze({
    title: "", text: "", hostname: h, hasPasswordField: false,
    hasEmailInput: false, insecureLogin: false, isEmail: false
  });
  check("plain real site stays silent: " + h, r.score < 4, true, "score " + r.score);
});

console.log(__fails === 0
  ? "PASS - all headless assertions held"
  : "FAIL (" + __fails + ") - this build is not shippable");
globalThis.__result = __fails;
`;

let src = "";
for (const f of FILES) src += fs.readFileSync(path.join(ROOT, f), "utf8") + "\n;\n";
src += ASSERTIONS;

// One script, one context: top-level `const` bindings are lexical, so running
// the sources and the assertions separately would leave the lists undefined.
const ctx = { console, URL, navigator: { language: "en" } };
vm.createContext(ctx);
try {
  vm.runInContext(src, ctx, { filename: "guardian-bundle.js" });
} catch (e) {
  console.log("RUN FAIL: " + e.message);
  process.exit(1);
}
process.exit(ctx.__result === 0 ? 0 : 1);
