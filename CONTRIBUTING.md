# Contributing to xihu-sword-ctf-agent

Thanks for your interest in contributing. This project is a **deterministic-first**
multi-agent framework for CTF solving. We value small, reproducible, honest
contributions over clever one-off hacks.

## Quick start for contributors

```bash
python -m venv .venv && .venv/Scripts/activate   # Windows
pip install httpx pytest                          # only external runtime dep + test dep
python scripts/_session_boot.py                   # optional local guard (ignored on CI)
pytest -q                                         # run the suite
```

## How the system is organized

- `core/`        — supervisor, planner, action executor, prompt assembly
- `agents/`      — `crypto_toolkit`, `misc_toolkit`, `web_toolkit`, `reverse`, `pwn`
- `skills/`      — 49 reusable deterministic skills; **the main extension surface**
- `llm/`         — provider client (whitelist-gated, budgeted, wall-clock stop-loss)
- `sandbox/`     — subprocess executor with an import allow-list
- `ctfplatform/` — platform pollers / submitters (e.g. DASCTF)
- `eval/`        — benchmark harness over `data/questions_real`
- `data/questions_real/` — historical CTF problems (flags auto-redacted)

## Adding a skill

A skill is a single markdown file `skills/<name>.md` with a `run(params) -> dict`
contract. Keep it deterministic and side-effect free where possible. Add a test
under `tests/` that exercises the happy path.

## Honesty policy (non-negotiable)

This repo was built around an **honest water-level** discipline:

- Never claim a solve that was a preset answer, a mock, or a self-authored target.
- KPI = real-link solves on `data/questions_real` only. `presolve` static-analysis
  hits are reported separately and do **not** count as LLM reasoning.
- Do not paste real flags or API keys. The pre-commit honesty scan blocks both.

Contributions that inflate numbers or hide limitations will be rejected.

## What we do NOT accept

- Internal competition problem resources (kept out of this public repo by design).
- Changes that disable the whitelist, budget, or stop-loss guards.
- "Just make it solve more" PRs without a reproducible benchmark delta.

## PR checklist

- [ ] `pytest -q` passes locally
- [ ] New behavior has a test or a benchmark delta
- [ ] No real flag / API key in diff
- [ ] KPI claims (if any) are backed by `eval.benchmark` output
