# 西湖论剑 CTF-Agent

> Chinese version: [README.zh.md](./README.zh.md)

> ⚠️ **Competition result disclaimer**: In the 20th West Lake Sword CTF preliminary round,
> this agent scored **0 accepted flags (0 effective submissions)** on the real platform.
> This README describes the agent's *engineering capabilities and governance*, **not** any
> competition score. Any "solved / pass-rate" claim without a platform `accepted` record
> refers to local offline analysis or sandbox testing only. Authoritative wording:
> `../deliverables/协同协议/真实战绩口径声明.md`.

> 🏷️ **History layering (2026-08-24)**: `git log` is the *archaeological layer* — it contains
> process noise (draft commits, reversions, concurrent-session churn). The *fact layer* is
> the tag `verified-2026-08-24` plus [`REAL_SOLVES_LEDGER.md`](./REAL_SOLVES_LEDGER.md).
> Cite facts from the ledger/tag, not from raw git history.

An AI agent for competitive CTF (Capture The Flag) that autonomously polls a DASCTF-style
platform, triages challenges, and submits flags — developed and exercised against the
**西湖论剑 (West Lake Sword Tournament)** competition (preliminary round: real platform accepted = 0).

**Private competition repository** — includes internal post-mortems, race data and
governance tooling. Not for public distribution.

## What it does

```
platform poll → triage/classify → attachment download + target-machine probe
             → deterministic skills (49) ⇄ LLM reasoning (whitelisted providers)
             → flag validation → platform submit (fail-closed on request errors)
```

- **Supervisor architecture**: `core/main_agent.py` plans per challenge,
  `core/supervisor_agent.py` enforces step budgets, tool-first discipline and
  request-failure vs wrong-flag separation (the post-incident fix for the
  submit-circuit-breaker bug).
- **Deterministic-first**: `skills/` holds 49 ready-to-run skills (crypto oracles,
  high-exponent RSA, base64 multilayer, big-file analysis, CMS source audit, …).
  A unified pre-solve layer (`core/presolve.py`) runs them before the LLM burns tokens.
- **Whitelisted LLM providers only** (competition rule §3); multi-source fallback with
  401/402 circuit breaking, per-question token budgets, heavy-model upgrade policy.
- **Race harness**: `scripts/_race_start.py --compete` = first-blood scan → stable
  polling → final report, with a **mandatory e2e data-link preflight (fail-closed)**.

## Hard gates (the lessons, codified)

| Gate | What | Enforced by |
|------|------|-------------|
| Test gate | real `pytest` run, no per-file fake loops | `setup.sh` (exit 1 on failure) |
| E2E gate | platform actually serves challenge data | `scripts/_e2e_verify.py`, wired into `--compete` |
| Network gate | proxy alive / LLM endpoints reachable / platform reachable | `scripts/_net_check.py` (trust_env=False) |
| Secret gate | no plaintext keys in staged files | pre-commit hook (`scripts/_scan_secrets.py`) |
| Write-lease gate | one writer per scope; out-of-scope commits rejected | `scripts/_lease.py` + pre-commit (CTDE governance) |

## Quick start

```bash
bash setup.sh                      # venv + deps + whitelist + net check + test gate
python scripts/_e2e_verify.py      # platform data link (when platform is up)
python scripts/_race_start.py --compete    # race mode (runs e2e preflight first)
```

Configuration via environment variables (see `config.py`): `DASCTF_TOKEN`,
`DASCTF_BASE_URL`, provider API keys. **Never commit keys** — the hook will refuse.

## Layout

```
core/          main agent + supervisor + presolve layer
agents/        domain toolkits (crypto, reverse, pwn, web, misc, …)
ctfplatform/   DASCTF client, poller, retry/fail-open submit path
skills/        49 deterministic skills + base data
scripts/       race launcher, e2e verify, net check, lease, scan
tests/         pytest gate (pytest.ini: -m "not slow" is the default baseline)
data/          challenge assets (tracked); runtime dirs gitignored
AGENTS.md      governance rules for every AI/human session (read first)
```

## Governance

This repository was built under parallel AI-agent sessions. The incident-driven
rules live in [`AGENTS.md`](./AGENTS.md); the multi-session coordination protocol
(normative layer) is paired with a machine-enforced write-lease (enforcement layer)
in `scripts/_lease.py`. Full competition post-mortems are in the parent directory's
`deliverables/` (kept out of this repo on purpose).

### Coordination state derives from git (2026-08-24, phase 5)

`scripts/_board.py` renders the live board **derived from git** — branch list
(`w/*` lanes = open tasks) + per-lane diff stats + `REAL_SOLVES_LEDGER.md` counts.
One-way data flow: git → board. Manual task-board/ledger bookkeeping is retired;
the write-lease is demoted to a lane-boundary hint (worktree isolation is the real
physical lock). The only auto-recorded ledger section (post-commit) stays as the
machine source of truth for commit attribution.
