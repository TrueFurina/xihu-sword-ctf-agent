# xihu-sword-ctf-agent

> 🌏 **中文文档 / Chinese documentation**: [README.zh.md](./README.zh.md)

> ⚠️ **Honesty disclaimer (read first)**: This project's real-world competition result on the live platform was **0 accepted flags**. All "solved / pass-rate" figures in this repo refer to **offline deterministic analysis** of historical CTF problems (the `data/questions_real/` corpus), not any live contest score. We do not claim LLM autonomous reasoning capability — the real capability here is a **deterministic static analyzer (presolve)** covering common CTF categories. See [Honest KPI](#honest-kpi) below.

An open-source **AI agent framework for CTF (Capture The Flag)** competitions. The agent polls a DASCTF-style platform, triages challenges, runs deterministic solvers first, and only escalates to an LLM when static analysis misses. Built and battle-tested against the *West Lake Sword Tournament (西湖论剑)* AI CTF track.

---

## Why this exists

Most "CTF agents" are just an LLM with a shell. This one is the opposite: **deterministic-first**. A pre-solve layer (`core/presolve.py`) fans out dozens of ready-to-run skills (RSA attacks, stego extractors, source-code auditors, base64 multilayer decoders, …) in parallel. The LLM is a last-resort escalator, behind a whitelist, a token budget, and a wall-clock stop-loss. The result is a system that is **reproducible, debuggable, and honest about what it can and cannot do**.

## Architecture

```
ctf_agent/
├── core/          main loop, presolve static analyzer, supervisor agent, wall-clock stop-loss
├── agents/        per-category solvers (crypto_toolkit / misc / web / reverse / pwn …)
├── skills/        49 deterministic skills (run(params) -> dict interface)
├── llm/           LLM client (provider whitelist, fail-closed circuit breaking)
├── ctfplatform/   contest-platform client (DASCTF-style), retry / fail-open submit path
├── sandbox/       code-execution sandbox (subprocess isolation)
├── eval/          historical-problem benchmark (honest KPI measurement)
├── data/questions_real/   historical problem corpus structure (flags redacted/placeholder)
├── config.py      config (defaults + environment-variable fallback)
├── run.py         entry point (--mode cli/web/mock)
└── setup.sh       environment bootstrap
```

### Solve pipeline

```
platform poll → triage/classify → attachment download + target probe
             → deterministic skills (49) ⇄ LLM reasoning (whitelisted providers)
             → flag validation → platform submit (fail-closed on request errors)
```

- **Supervisor architecture**: `core/main_agent.py` plans per challenge, `core/supervisor_agent.py` enforces step budgets, tool-first discipline, and the request-failure-vs-wrong-flag separation (the post-incident fix for a submit-circuit-breaker bug).
- **Deterministic-first**: `skills/` holds 49 runnable skills. `core/presolve.py` runs them before any LLM token is spent.
- **Whitelisted LLM only** (contest rule §3); multi-source fallback with 401/402 circuit breaking, per-question token budgets, heavy-model upgrade policy.
- **Race harness**: `scripts/_race_start.py --compete` = first-blood scan → stable polling → final report, with a mandatory e2e data-link preflight (fail-closed).

## Hard gates (lessons, codified)

| Gate | What | Enforced by |
|------|------|-------------|
| Test gate | real `pytest` run, no per-file fake loops | `setup.sh` (exit 1 on failure) |
| E2E gate | platform actually serves challenge data | `scripts/_e2e_verify.py`, wired into `--compete` |
| Network gate | proxy alive / LLM endpoints reachable | `scripts/_net_check.py` (`trust_env=False`) |
| Secret gate | no plaintext keys in staged files | pre-commit hook (`scripts/_scan_secrets.py`) |
| Write-lease gate | one writer per scope; out-of-scope commits rejected | `scripts/_lease.py` + pre-commit |

## Quick start

```bash
cd ctf_agent
bash setup.sh                      # venv + deps + whitelist + net check + test gate
export CTF_AGENT_LLM_PROVIDER=deepseek
export CTF_AGENT_LIGHT_MODEL=deepseek-chat
export DEEPSEEK_API_KEY=sk-xxx     # your key — never commit it
.venv/Scripts/python.exe run.py --mode mock --category crypto   # offline smoke test
.venv/Scripts/python.exe run.py --mode cli                      # local practice
```

Configuration is environment-variable driven (see `config.py`): `DASCTF_TOKEN`, `DASCTF_BASE_URL`, provider API keys. **Never commit keys** — the hook refuses.

## Honest KPI

The single machine-enforced KPI is **`offline_verified`** — the number of *historical real problems* for which a complete, reproducible attack chain produced a flag matching the problem's ground-truth `flag_sha256` (see `REAL_SOLVES_LEDGER.md`, guarded by the merge-gate ratchet in `scripts/_merge_gate.py` so it can only go up, never down).

| Metric | Result |
|--------|--------|
| **offline_verified** (strict real-problem KPI) | **9** |
| Deterministic pipeline coverage (`data/questions_real/` 15) | **14 / 15** (presolve direct-solve coverage — NOT a "solved" claim) |
| LLM autonomous-reasoning contribution | **0** (all 9 verified solves are deterministic presolve/tooling; zero LLM reasoning) |

> ⚠️ **What `offline_verified=9` does and does NOT mean.** It is the count of *real past-CTF problems* (provenance=`real_past_ctf`, sha256-verified, machine-counted by `scripts/_merge_gate.py count_offline_verified`) solved by a **reproducible deterministic pipeline** — a real engineering milestone, but **NOT a capability measurement**. These problems' writeups are public and almost certainly in LLM pre-training corpora (contamination risk — see `data/results/CTF-Agent深度评审报告_20260828.md` G1). LLM autonomous-reasoning contribution is **0/9**. Treat 9 as "template coverage of memorizable public problems," never as "reasoning ability." (Note: `real_crypto_ezrsa` / `real_crypto_simplelegendre` / `real_crypto_exciting_inverse` were historically solved manually but are **not currently reproducible** by the deterministic pipeline — they were removed from the strict KPI on 2026-08-28 after `presolve` returned `None` for all three; see `KNOWN_GAP`.)

> **LLM reasoning break-ice experiment (not counted in KPI)**: With `scripts/_llm_breaking_ice.py --no-internal-presolve` (presolve shortcuts disabled, LLM forced to reason), `10/15` historical problems were solved by `main_agent_llm` autonomous reasoning (crypto×6 / reverse×3 / web×1; all sha256-verified). This proves real LLM reasoning capability exists, but it is **not** counted in `offline_verified` — that KPI only admits strict sha256-verified solves, and the 9 it holds are presolve-deterministic. Details in `MEMORY.md`.

Interpretation: **capability = static-analyzer coverage**, not LLM reasoning. To solve more problem types, write more deterministic skills. We say this plainly because over-claiming is the easiest way to embarrass an open-source security tool.

## Security & compliance

This repo publishes the **engineering skeleton and methodology only**. Red lines:

1. **Real flags are never published.** All plaintext flags are stripped; only `<REDACTED>` / sha256 placeholders remain. Truth files live in `.gitignore`.
2. **No secrets in the repo.** LLM keys and platform tokens are injected via env vars / registry only.
3. **Internal contest resources are excluded** (`data/race_details/`, attachments, signatures) via `.gitignore`.
4. **Honest water-level.** We do not exaggerate capability. See above.

## License

[MIT](LICENSE) — open for learning and research. Respect each CTF's rules and platform terms.
