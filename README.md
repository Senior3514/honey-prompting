# Honey Prompting: a Claude skill

Version 1.2.2. Web page: https://honeyprompter.com/skill

Honey Prompting teaches Claude to plant decoys (fake, inert secrets) and canaries (hidden instructions with a unique token) where an AI agent can see them, then run an offline self-test and report what was caught. Use it for chatbots, RAG pipelines, MCP servers, coding agents and other tool-using assistants that read untrusted text.

**It detects. It does not prevent.** A decoy that leaks, or a canary that gets obeyed, is evidence that a leak path exists. A quiet result is not proof of safety, and this skill does not replace least privilege, filtering, or human approval of sensitive actions. See `references/limits.md` for what it cannot catch.

No account and no API key are needed. The self-test calls no model and sends nothing. Connecting a HoneyPrompter console is optional.

## Install

### Claude Code

Put this folder at `~/.claude/skills/honey-prompting/` (every project) or `.claude/skills/honey-prompting/` (one project):

```bash
git clone https://github.com/Senior3514/honey-prompting ~/.claude/skills/honey-prompting
```

Check: `ls ~/.claude/skills/honey-prompting/SKILL.md`. Then ask Claude: "Use the honey-prompting skill to add decoys and canaries to this agent."

The page at https://honeyprompter.com/skill also has a one-line installer that verifies the zip's SHA-256.

### Claude app (Claude.ai, desktop, mobile)

Download `honey-prompting-skill.zip` from https://honeyprompter.com/skill and add it under Settings, in Skills or Capabilities. Uploading skills needs a plan that supports it. The chat app cannot run the SDK, so the skill walks you through a published self-test report and says it did not run it live.

## Contents

- `SKILL.md`: the skill instructions
- `references/`: SDK usage, placement playbook, limits, other languages, a stored self-test report
- `scripts/hp_decoys.py`: mint decoys and scan text for them (Python standard library only)

The self-test itself uses the `honeyprompts` Python package, downloaded from www.honeyprompter.com and checked against a pinned SHA-256 (see step 1 in `SKILL.md`).

## License

Apache-2.0 (see `LICENSE`). It covers only the skill files in this repository; see `NOTICE`.
