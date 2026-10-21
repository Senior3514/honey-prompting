# Honey Prompting in a stack that is not Python

The SDK is Python. The idea is four steps in any language. Do them in this order and keep each small.

1. **Mint decoys.** Random, plausible-looking, inert values with a recognisable prefix (`AKIA-HONEY-…`, `sk-honey-decoy-…`). Store them privately (a secrets store or a 0600 file), one per place you will plant them.
2. **Put them in context.** The system prompt, a tool config block, a fake `.env` in memory, a row in a retrieved document. One decoy per place, so a hit says where it came from.
3. **Scan every model output before it leaves.** The reply, each tool-call argument, text bound for a webhook or a file. Match the value as written, in another case, spaced out, reversed, ROT13, base64, hex and URL-encoded.
4. **On a hit: block, say nothing about it to the model, and record a receipt.** Return a fixed safe message, and keep the decoy id, the agent id, the time, and the blocked text.

`scripts/hp_decoys.py` in this skill implements steps 1 and 3 with no dependencies (`mint`, `scan`, `selftest`). Run it on any output to see the matching rules. Port it, or call it as a subprocess, but keep the same forms.

## A small TypeScript / JavaScript version

```js
import { randomBytes } from "node:crypto";

export const mint = () => ({ id: "aws-1", value: "AKIA-HONEY-" + randomBytes(8).toString("hex").toUpperCase() });

const forms = (t) => {
  const out = [t, t.toLowerCase(), [...t].reverse().join("")];
  out.push(t.replace(/(?:%[0-9A-Fa-f]{2})+/g, (m) => { try { return decodeURIComponent(m); } catch { return m; } }));
  for (const run of t.match(/[A-Za-z0-9+/_-]{16,}={0,2}/g) ?? []) {
    try { out.push(Buffer.from(run, "base64").toString("utf8")); } catch {}
  }
  for (const run of t.match(/(?:[0-9a-fA-F]{2}){12,}/g) ?? []) out.push(Buffer.from(run, "hex").toString("utf8"));
  out.push(t.replace(/[\s*`'"_.\-|,;:]+/g, "").toLowerCase());
  return out;
};

export const leaked = (text, decoy) => {
  const needle = decoy.value.toLowerCase();
  const squashed = needle.replace(/[\s*`'"_.\-|,;:]+/g, "");
  return forms(text).some((f) => f.toLowerCase().includes(needle) || f.includes(squashed));
};
```

This snippet catches the whole value as written, in another case, split by spaces or punctuation, reversed, base64, hex, or URL-encoded. It does not catch ROT13, invisible characters or look-alike Unicode, a partial value (a fragment), or a paraphrase. Add ROT13, Unicode normalisation (NFKC plus stripping invisible characters, as `scripts/hp_decoys.py` does) and fragment matching if you need them, and accept that a determined attacker can always describe a secret in words (see `limits.md`).

Wrap the call so a hit is handled in one place:

```js
async function guarded(call, decoys, onHit) {
  const reply = await call();
  const hit = decoys.find((d) => leaked(JSON.stringify(reply), d));
  if (hit) { onHit(hit); return { role: "assistant", content: "Sorry, I can't help with that." }; }
  return reply;
}
```

Record a receipt: the decoy id, the agent id, the time, and the blocked text.
