# What to tell the user it cannot do

Use these plain statements in the final note. They are not disclaimers to bury; they are the product's honest edge.

## What a hit proves

- **A decoy hit** proves that text containing the decoy left the model. It proves a leak path exists. It does not prove who asked or why.
- **A canary hit** proves something requested the URL. It does not prove which model did, or that the agent is compromised. Mail and chat tools pre-fetch links; a link previewer or scanner can look like an attacker. Read the client type before escalating.
- **A receipt** proves a record was stored. It does not prove the event was malicious.

## What it does not catch

- A leak that is **paraphrased, translated or spelled out in words** ("Alfa Kilo India Alfa…"), or only a **piece shorter than 12 characters**. A contiguous run of 12 or more characters from the decoy is matched, including that run in base64, hex, or URL-encoding.
- Harm that never quotes a secret: a destructive tool call, a wrong answer, a quiet data change.
- An agent that never reads the canary, or a model that ignores the hidden instruction. Silence is not safety.
- Anything the tripwire was not wired to see. A decoy in the system prompt does not cover a secret in a tool config.

## What it does not replace

Least privilege for the agent's tools and credentials, input and output filtering, human approval for sensitive actions, rate limits and monitoring. Honey Prompting tells you when those failed.

## Wording for the final note

> Covered: [tripwires and where they are]. Detects: [leak of the decoy in these forms; a read of the canary file; request to the canary URL]. Blocks: [the reply that contains a decoy]. Does not cover: [paraphrased leaks, harm without a secret, anything outside these tripwires]. To re-check: run `honeyprompt selftest` and the tripwire tests in the suite.

Never write "secure", "safe", "protected from prompt injection" or "prevents".

## Related work (do not claim to have invented it)

The underlying idea, canary and honeytoken style tripwires, is older than LLMs. Related public work includes the USENIX Security 2025 paper "Cloak, Honey, Trap: Proactive Defenses Against LLM Agents", WunderGraph's honeypot functions, and Thinkst Canarytokens. Say what this skill adds (decoys and canaries feeding one evidence trail with alerts), not that it is the first.
