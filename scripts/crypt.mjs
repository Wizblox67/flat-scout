// Flat Scout data lock. The code (PIN) comes from the FS_PIN environment variable, never from this file.
// Usage:
//   FS_PIN=xxxxxx node scripts/crypt.mjs encrypt data.json data.enc.json
//   FS_PIN=xxxxxx node scripts/crypt.mjs decrypt data.enc.json data.json
import { readFileSync, writeFileSync } from "node:fs";
const { subtle } = globalThis.crypto;
const ITER = 600000;
const b64 = (u8) => Buffer.from(u8).toString("base64");
const unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));

async function keyFrom(pin, salt, iter) {
  const base = await subtle.importKey("raw", new TextEncoder().encode(pin), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

const [, , cmd, input, output] = process.argv;
const pin = process.env.FS_PIN;
if (!pin || !["encrypt", "decrypt"].includes(cmd) || !input || !output) {
  console.error("Usage: FS_PIN=... node scripts/crypt.mjs encrypt|decrypt <in> <out>");
  process.exit(2);
}

if (cmd === "encrypt") {
  const text = readFileSync(input, "utf8");
  const data = JSON.parse(text); // fails loudly on invalid JSON
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await keyFrom(pin, salt, ITER);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(data))));
  const r = (data.reports || [])[0] || {};
  const s = r.stats || {};
  const out = {
    v: 1, kdf: "PBKDF2-SHA256", iter: ITER, salt: b64(salt), iv: b64(iv), ct: b64(ct),
    // Public, non-sensitive sync info so the phone can show "last update" before unlocking.
    sync: { at: data.updated || new Date().toISOString(), newToday: (s.gem || 0) + (s.watch || 0) + (s.maybe || 0), report: r.date || null }
  };
  writeFileSync(output, JSON.stringify(out));
  console.log(`encrypted ${input} -> ${output} (sync.at=${out.sync.at})`);
} else {
  const env = JSON.parse(readFileSync(input, "utf8"));
  const key = await keyFrom(pin, unb64(env.salt), env.iter);
  let pt;
  try { pt = await subtle.decrypt({ name: "AES-GCM", iv: unb64(env.iv) }, key, unb64(env.ct)); }
  catch { console.error("Wrong code or damaged file."); process.exit(1); }
  const data = JSON.parse(new TextDecoder().decode(pt));
  writeFileSync(output, JSON.stringify(data, null, 1));
  console.log(`decrypted ${input} -> ${output}`);
}
