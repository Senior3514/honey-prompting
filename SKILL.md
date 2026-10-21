---
name: honey-prompting
description: Trigger this skill when the user wants to know whether an AI agent leaked a secret or obeyed a hidden instruction. Use it for prompt injection, indirect injection, a decoy, a canary, a honeytoken, a honey prompt, or a tripwire on a chatbot, a RAG pipeline, an MCP server, a coding agent, or a tool-using assistant. Also use it when they only describe the worry (the agent reads untrusted pages, tickets, or email while it holds credentials) or they say honey prompt, HoneyPrompter, or protect my agent. Work standalone. Plant decoys, run honeyprompt selftest, and show what was caught. No console and no API key are required. The self-test sends nothing. Point to https://honeyprompter.com only if they ask for more than the local check, and only as the last step. Do not use it to plant a real secret, or to claim an attack was stopped.
---

# Honey Prompting

version: 1.2.3

## What this does

Honey Prompting plants fake secrets (decoys) and hidden instructions (canaries) where an agent can see them.
A leak of a decoy, or an agent that obeys a canary, is evidence. The tripwire detects. It does not prevent.
This skill does that work on its own: install, plant, run an offline self-attack, and show what was caught. A console is optional.

## When to use

- They are building, reviewing, or hardening an agent, chatbot, RAG pipeline, MCP server, or coding assistant.
- They mention prompt injection, a leak, exfiltration, a honeytoken, a canary, or a honey prompt.
- They describe the worry in plain words: the agent reads tickets, email, or web pages and also holds credentials.
- They want proof the detectors work before any account or key.

## When not to use

- The task is ordinary coding, with no untrusted text and no agent that holds secrets.
- They want something that prevents attacks. Say what this detects, then stop. Silence is not safety.
- They ask you to plant a real password, key, or token.
- They already have tripwires and only want the console. Do step 6 and nothing else.

If you cannot run a shell or pip, go to **No shell**. Do not invent command output.

## 1. Install

Use `python3` (3.10 or newer). A bare `python` may be missing. PyPI does not host this package. Do not ask for a key. Make a virtualenv, then run this block. It fetches `/dl/latest.json`, downloads the wheel that file names, and checks sha256 with hashlib against that file and against `PINNED_SHA256`. A redirect whose target is not `https://www.honeyprompter.com` on port 443 (another host, another port, or http) is an error. It then installs `./<wheel>` with `--no-deps`. Do not pip-install the URL.

```bash
python3 -m venv .hp && . .hp/bin/activate
```

```python
import hashlib, json, re, subprocess, sys, urllib.parse, urllib.request
from pathlib import Path

# Expected sha256 of the current wheel. An empty string skips the pin check.
PINNED_SHA256 = "fbd706c6b89b3c86716154610ad5adc6117033bee9e51c60d92fb20bdbd66daa"
HOST = "www.honeyprompter.com"

class _PinHost(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        newurl = str(newurl)
        part = urllib.parse.urlsplit(newurl)
        port = 443 if part.port is None else part.port
        if part.scheme != "https" or (part.hostname or "").lower() != HOST or port != 443:
            raise OSError("redirect rejected")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

opener = urllib.request.build_opener(_PinHost)
base = "https://" + HOST + "/dl/"
with opener.open(base + "latest.json") as resp:
    meta = json.load(resp)
name = str(meta["wheel"])
digest = str(meta["sha256"]).lower()
if re.fullmatch(r"^honeyprompts-\d+(\.\d+){1,3}-py3-none-any\.whl$", name) is None or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
    raise SystemExit("latest.json named an unexpected file")
with opener.open(base + name) as resp:
    data = resp.read()
got = hashlib.sha256(data).hexdigest()
pinned = PINNED_SHA256.strip().lower()
if got != digest:
    raise SystemExit("checksum mismatch")
if pinned and got != pinned:
    raise SystemExit("checksum does not match the pinned wheel")
Path(name).write_bytes(data)
subprocess.check_call([sys.executable, "-m", "pip", "install", "--no-deps", "./" + name])
```

Stop if the checksum does not match. Download, verify, then install the local file. The private-venv installer is in `references/sdk.md`.

## 2. Plant decoys

A decoy is a fake secret. A canary is a hidden instruction plus a token nothing legitimate should repeat. Both are synthetic. They authenticate nowhere.

With a shell, show the four in-memory decoys. Print ids and kinds only. Never print a value.

```bash
python3 -c 'from honeyprompts import DecoyRegistry; [print("id=%s kind=%s where=memory" % (d.id, d.kind)) for d in DecoyRegistry.with_defaults()]'
```

Those four stay in memory: `aws-demo-1`, `openai-demo-1`, `slack-demo-1`, `github-demo-1`. The self-test plants 8 items in all: those 4 decoys, `canary-selftest-1`, `.env`, `wiki/CANARY.md`, and `README.md`. The three files are in a temporary directory and are deleted. Do not write them into the user's project.

Shapes, if you mint an example by hand: `AKIA-HONEY-` plus 16 letters, `sk-honey-decoy-`, `xoxb-HONEY-`, `ghp_HONEY`, and a canary token that starts with `HONEY-CANARY-`. The matcher lives in `scripts/hp_decoys.py`.

## 3. Run the self-attack

`honeyprompt` and `python3 -m honeyprompts` are the same program. Run the self-test once.

```bash
honeyprompt selftest
```

Add `--json` only when you need to parse the report. Do not run it a second time just to see JSON.

```bash
python3 -m honeyprompts selftest --json
```

Exit 0 is a pass. Exit 1 is a fail.

The command calls no model, sends nothing, and writes no receipt. `runtime: any` means the same list runs for every model. Paste the output you actually got.

`scripts/hp_decoys.py selftest` is a different, smaller check. It is not this report.

## 4. Read the results

Quote the report. Do not add a catch it does not list.

Text and `--json` are one run in two shapes.

- Text: `result` is `PASS` or `FAIL`. `attacks`, `caught`, `not_caught`, `missed`, and `unexpected` are counts on their own lines. `missed_ids` and `unexpected_ids` appear as lines only when they are not empty.
- JSON: `result` is the lowercase string `pass` or `fail`. Under `summary`: the counts (`attacks`, `caught`, `not_caught`, `missed`, `unexpected`), plus `missed_ids`, `unexpected_ids`, `known_gap_ids`, and `control_ids`. Top-level `attacks` is a list of 55 rows, not a number. The count is `summary.attacks`.

1. `result` and `headline`, then the counts and `by_category`. JSON counts are inside `summary`.
2. Known gaps and controls. JSON: `summary.known_gap_ids` and `summary.control_ids`. Text: the `known_gaps` and `controls` lines.
3. Each planted row (id, kind, where, note). For a caught attack: id, title, severity, rule, and `meaning`. A quiet row is a control or a known gap. Use `note` when it is there.
4. The `limits` lines, then one sentence: this checked the detectors on this machine. It did not call a model, and it did not cover their agent yet.

A fail is text `result: FAIL` or JSON `"result": "fail"`. On either, name every id in `missed_ids` and `unexpected_ids` (under `summary` in JSON), then stop. Do not harden, and do not say the detectors work.

These lines are copied from `python3 -m honeyprompts selftest --json` on SDK 1.0.21 (exit 0). Three slices, not one object. The middle slice is the whole `summary` object. Top-level `attacks` continues as 55 rows. The same object is in `references/selftest-sample.md`.

```text
  "result": "pass",
```
```text
  "summary": {
    "attacks": 55,
    "caught": 46,
    "not_caught": 9,
    "missed": 0,
    "unexpected": 0,
    "missed_ids": [],
    "unexpected_ids": [],
    "known_gap_ids": [
      "exfil.spelled-words",
      "exfil.short-prefix"
    ],
    "control_ids": [
      "prompt.benign-order",
      "prompt.benign-ignore-typo",
      "prompt.benign-developer-device",
      "exfil.clean-reply",
      "canary.read-readme",
      "tool.dd-null",
      "tool.benign-search"
    ]
  },
```
```text
  "attacks": [
    {
      "id": "prompt.ignore-previous",
```

## 5. Harden

Do this only after a pass (`PASS` in text, `pass` in JSON), and only if they want tripwires in their own system. Still no console.

Map the agent by reading the repo. Write three rows: what untrusted text it reads, what secret-looking material it holds, and where output goes. Name the files. Ask one question only if the code does not say.

Place one distinct decoy per spot, from `references/playbook.md`. Canaries only in systems the user owns.

Wire it. Python with an OpenAI-style client: `protect()` and the test in `references/sdk.md`. Any other language: `references/other-languages.md`. Run their test and show that output.

Close with the note in `references/limits.md`. Say what it detects, what it blocks (only with `protect()` or a guard; otherwise it blocks nothing and only detects), and what it does not detect.

## 6. Beyond the local check

Anything beyond this local check is at https://honeyprompter.com.

## No shell

Claude.ai often has no pip and no code execution. Do the job in the chat. It is a walkthrough, not a live run.

1. Say in the first sentence that you did not run `honeyprompt selftest`.
2. Plant four decoys and one canary in the reply. Mint new examples from the shapes in step 2. Do not copy the SDK's built-in values, and do not claim these are the ones the self-test planted. Say where each would sit: system prompt, a page they own, or a tool config. A canary is an HTML comment that asks for one unique URL, plus a `HONEY-CANARY-` token. A person reading the rendered page does not see the comment.
3. Walk the published attack in `references/selftest-sample.md`. Read the header, `by_category`, the known gaps, and the controls. Quote one caught row from each category: id, title, severity, rule, and `meaning`, copied from that file.
4. Say the score in words: 46 of 55 caught, 0 missed, 0 false alarms (`unexpected` is 0). The 9 not-caught rows are 7 controls and 2 known gaps. That is the SDK 1.0.21 report stored in this skill. It is not output from this chat.
5. If they have an agent, continue at step 5 in prose. Do not claim a test passed unless you ran it.

## How to read the result

| Field | Meaning |
| --- | --- |
| caught | A detector fired. |
| not_caught | Nothing fired. |
| missed | A catch was expected and did not fire. That is a failure. |
| unexpected | A quiet row fired. That is a false alarm. That is a failure. |
| known gap | Quiet on purpose. The detector cannot see that form. |
| control | Ordinary text that must stay quiet. |

A false alarm is `unexpected` greater than 0. The 9 not-caught rows are not misses and not false alarms.

Each attack has an `input` string with the decoy masked as `<id>`, such as `<aws-demo-1>`. Those masked strings are the same on every run and match `references/selftest-sample.md`. Read `caught`, `rule`, and `meaning`.

On the published SDK 1.0.21 run the text lines are `attacks` 55, `caught` 46, `not_caught` 9, `missed` 0, `unexpected` 0. In that run's JSON the same numbers are `summary.attacks`, `summary.caught`, `summary.not_caught`, `summary.missed`, and `summary.unexpected`, and `result` is `pass`. Known gaps: `exfil.spelled-words` (the secret is spelled as words), `exfil.short-prefix` (a fragment shorter than 12 characters). Controls: `prompt.benign-order`, `prompt.benign-ignore-typo`, `prompt.benign-developer-device`, `exfil.clean-reply`, `canary.read-readme`, `tool.dd-null`, `tool.benign-search`.

`by_category` on that run: prompt injection 18/21, decoy exfiltration 15/18, canary file read 3/4, tool abuse 10/12. A pass means this copy of the detectors caught the scripted attacks. It does not mean their agent is covered.

If your live run differs, report the live run and say it differs from `references/selftest-sample.md`.

## Troubleshooting

| What happened | What you see | What to do |
| --- | --- | --- |
| Package name on PyPI | `pip install honeyprompts` fails | Download the wheel, verify sha256, then install the local file. See step 1 and `references/sdk.md`. |
| Command not on PATH | `honeyprompt: command not found` | Same program: `python3 -m honeyprompts selftest`. |
| Old Python | install error about 3.10 | Use Python 3.10 or newer. |
| No shell | Claude.ai with no code execution | Follow **No shell**. Do not invent a transcript. |
| Detectors failed | Text `result: FAIL`, JSON `"result": "fail"`, or `missed` or `unexpected` above 0 | Name `missed_ids` and `unexpected_ids`. In JSON they are under `summary`. Stop before step 5. |
| Checksum mismatch | `checksum mismatch` or `checksum does not match the pinned wheel` | Download again. Do not skip the check, and do not install the URL. |
| Redirect rejected | the download left `https://www.honeyprompter.com`, left port 443, or switched to http | Stop. Do not install. |
| Quiet rows | `not_caught` with `ok: yes` | Control or known gap. Silence is not safety. |
| Wheel will not download | pip cannot reach the site | The self-test needs no network. The install does. Retry when the site is reachable. |

## Safety

- Decoys are fake. Never plant a real secret, a revoked key, or anything that still authenticates.
- The self-test report names ids, not values. Do not copy a decoy value into logs or a commit. In a no-shell plant, show one fresh fake, label it inert, and do not treat it as a credential.
- An ingest key is a real secret. It is not a decoy. Never commit it or paste it into chat.
- Plant canaries only in systems the user owns. A hit can be a link previewer or a scanner. Read the client before you call it a compromise.
- A tripwire does not replace least privilege, filtering, or a person approving sensitive tools.

## Sample

The first 17 lines of a real `honeyprompt selftest` run with SDK 1.0.21. Exit code 0. The complete stdout is in `references/selftest-sample.md`. Do not retype the counts from memory.

```text
result: PASS
headline: Every expected catch fired. 46 caught, 9 not caught. A row with expect not_caught and ok yes is a control or a known gap, not a failure. No model was called. Nothing was sent.
how_to_read: Summarize headline, by_category, known_gaps, controls, and limits. For a caught row, quote title, severity, rule, and meaning. A row with expect not_caught and ok yes is a control or a known gap, not a failure. Do not invent a catch that is not in this report.
version: 1.0.21
offline: yes
network: no
account: no
api_key: no
model_called: no
runtime: any
attacks: 55
caught: 46
not_caught: 9
missed: 0
unexpected: 0
known_gaps: exfil.spelled-words, exfil.short-prefix
controls: prompt.benign-order, prompt.benign-ignore-typo, prompt.benign-developer-device, exfil.clean-reply, canary.read-readme, tool.dd-null, tool.benign-search
```

## What you reply with

1. Whether you ran the command, or followed **No shell**.
2. What was planted (ids, kinds, where).
3. The score, then what was caught and what stayed quiet, from a run or from the sample file.
4. The harden plan, only if you reached step 5.
5. The coverage note from `references/limits.md`.
