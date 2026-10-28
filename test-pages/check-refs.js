// Every guardian* function a script calls must actually exist in the files
// that script loads.
//
// This exists because it did not: restructuring the popup deleted
// guardianQuietHere but left the call to it, so every press of "Is this a
// scam?" threw a ReferenceError that the outer catch swallowed into "We could
// not check this page". Nothing on screen, nothing in the page console - the
// error only appears in the POPUP's own console, which almost nobody opens.
//
//   node test-pages/check-refs.js
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const man = JSON.parse(fs.readFileSync(path.join(ROOT, "manifest.json"), "utf8"));

// Which files load together, per execution context.
const contexts = [];
man.content_scripts.forEach((cs, i) =>
  contexts.push({ name: "content script " + i, files: cs.js })
);
contexts.push({
  name: "service worker",
  files: ["data/strings.js", "data/allowlist.js", "data/ad-networks.js", "background.js"]
});
// The popup loads its own <script> tags.
const popup = fs.readFileSync(path.join(ROOT, "popup/popup.html"), "utf8");
contexts.push({
  name: "popup",
  files: (popup.match(/<script src="([^"]+)"/g) || [])
    .map((m) => m.match(/src="([^"]+)"/)[1])
    .map((s) => path.posix.normalize(path.posix.join("popup", s)))
});
// The demo reel, when present. It is not part of the shipped extension, so
// this same check has to pass inside a release package that leaves it out.
const demoPath = path.join(ROOT, "demo/guardian-demo.html");
if (fs.existsSync(demoPath)) {
  const demo = fs.readFileSync(demoPath, "utf8");
  contexts.push({
    name: "demo reel",
    files: (demo.match(/<script src="([^"]+)"/g) || [])
      .map((m) => m.match(/src="([^"]+)"/)[1])
      .map((s) => path.posix.normalize(path.posix.join("demo", s)))
  });
}

let fails = 0;
for (const ctx of contexts) {
  let src = "";
  for (const f of ctx.files) {
    const p = path.join(ROOT, f);
    if (!fs.existsSync(p)) {
      fails++;
      console.log(ctx.name + ": missing file " + f);
      continue;
    }
    src += fs.readFileSync(p, "utf8") + "\n";
  }
  const defined = new Set();
  for (const m of src.match(/function\s+(guardian[A-Za-z0-9_]*)/g) || []) {
    defined.add(m.replace(/function\s+/, ""));
  }
  for (const m of src.match(/(?:const|let|var)\s+(guardian[A-Za-z0-9_]*)\s*=/g) || []) {
    defined.add(m.replace(/(?:const|let|var)\s+/, "").replace(/\s*=$/, "").trim());
  }
  const called = new Set();
  for (const m of src.match(/\b(guardian[A-Za-z0-9_]*)\s*\(/g) || []) {
    called.add(m.replace(/\s*\($/, "").trim());
  }
  for (const name of called) {
    if (!defined.has(name)) {
      fails++;
      console.log(ctx.name + ": calls " + name + "() but nothing defines it");
    }
  }
}
console.log(fails === 0
  ? "PASS - every guardian function called is defined in its context"
  : "FAIL (" + fails + ")");
process.exit(fails === 0 ? 0 : 1);
