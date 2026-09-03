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
├── skills/        52 deterministic skills (run(params) -> dict interface)
├── llm/           LLM client (provider whitelist, fail-closed circuit breaking)
├── ctfplatform/   contest-platform client (DASCTF-style), retry / fail-open submit path
├── sandbox/       code-execution sandbox (subprocess isolation)
├── eval/          historical-problem benchmark (honest KPI measurement)
├── data/questions_real/   historical problem corpus (most flags SHA-256; a few long-public events e.g. Anxun Cup 2020 retain plaintext; 2026 contest excluded)
├── config.py      config (defaults + environment-variable fallback)
├── run.py         entry point (--mode cli/web/mock)
└── setup.sh       environment bootstrap
```

### Solve pipeline

```
platform poll → triage/classify → attachment download + target probe
             → deterministic skills (52) ⇄ LLM reasoning (whitelisted providers)
             → flag validation → platform submit (fail-closed on request errors)
```

- **Supervisor architecture**: `core/main_agent.py` plans per challenge, `core/supervisor_agent.py` enforces step budgets, tool-first discipline, and the request-failure-vs-wrong-flag separation (the post-incident fix for a submit-circuit-breaker bug).
- **Deterministic-first**: `skills/` holds 52 runnable skills. `core/presolve.py` runs them before any LLM token is spent.
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
| **offline_verified** (strict real-problem KPI) | **12** |
| Deterministic pipeline coverage (presolve direct-solve, early 15-problem subset) | **15 / 15** (presolve direct-solve coverage — NOT a "solved" claim; full 92-problem corpus coverage tracked in REAL_SOLVES_LEDGER.md; `real_misc_vnctf_flag` 2026-09-03 governance fix —题面 `flag_pattern` 修订 + vision LLM 兜底链路修复后正式入 presolve) |
| LLM autonomous-reasoning contribution | **0** (all 12 verified solves are deterministic presolve/tooling; zero LLM reasoning) |
| Regression-set reproducible count | **13 / 13** (12 题集 presolve + 1 题 10732 治理修复：`scripts/verify_10732.py` 可机器复现攻击链；REGRESSION_CHECKS 13 道全过；10732 **不进** PROMOTION_EVIDENCE 因无外部 sha256 真值闭环，详见台账题块 2 + `scripts/_antifraud.py` 顶部注释 2026-09-03 治理段) |

> ⚠️ **What `offline_verified=12` does and does NOT mean.** It is the count of *real past-CTF problems* (provenance=`real_past_ctf`, sha256-verified, machine-counted by `scripts/_merge_gate.py count_offline_verified`) solved by a **reproducible deterministic pipeline** — a real engineering milestone, but **NOT a capability measurement**. These problems' writeups are public and almost certainly in LLM pre-training corpora (contamination risk — see `data/results/CTF-Agent深度评审报告_20260828.md` G1). LLM autonomous-reasoning contribution is **0/12**. Treat 12 as "template coverage of memorizable public problems," never as "reasoning ability." (Note: on 2026-08-28 the KPI was honestly cut back from a nominal 12 to 9 because three solves — `real_crypto_ezrsa`, `real_crypto_simplelegendre`, `real_crypto_exciting_inverse` — were not reproducible by the deterministic pipeline. All three were promoted **back into the strict KPI on 2026-09-03 with evidence**, each via a deterministic solver wired into presolve and returning `REGRESS_PASS` with sha256 matching ground truth: `real_crypto_ezrsa` — Håstad broadcast solver `skills/crypto_hastad_broadcast.py` (`_try_hastad_broadcast`, e=17, CRT+iroot); `real_crypto_simplelegendre` — Legendre-symbol solver `skills/crypto_legendre_phi.py` (`_try_legendre_phi`, phi-leak factorization + per-bit `(c|p)=(-1)^bi`); `real_crypto_exciting_inverse` — phi+dual-modular-inverse solver `skills/crypto_modinv_factor.py` (`_try_modinv_factor`, CRT⟹`A·p+B·q=N+1`⟹quadratic-root factorization). This 12 is therefore a fully evidence-backed count, unlike the pre-rollback 12. See `PROMOTION_EVIDENCE` in `scripts/_antifraud.py` and blocks 7/8/11 of `REAL_SOLVES_LEDGER.md`.) **2026-09-03 governance fix (no KPI change)**: `real_misc_vnctf_flag` was historically ledgered as A-class ✅ but the problem JSON had `flag_pattern` written as `flag\{[^}]+\}` while the true flag is `vnctf\{...\}` — presolve's secondary regex check misclassified the skill's sha256-verified output as "bait" and dropped it. Fixed the pattern, repaired the venv's broken `certifi` (force-reinstalled `certifi==2026.7.22` because RECORD file was missing, blocking `httpx` from finding the CA bundle), and confirmed `scripts/_regress_one.py real_misc_vnctf_flag` → `REGRESS_PASS (5159ms)` via the existing `skills/misc_grid_resample.py` (grid-resample deterministic algorithm + baidu `ernie-4.5-turbo-vl` vision-LLM OCR fallback, sha256-gated return). The solve was already counted in the 9-baseline `BASE_AUTHORIZED_KPI_SOLVES`; this fix moves it from "fake-reproducible-but-counted" to "genuinely-reproducible-and-counted", closes the `KNOWN_GAP` entry, and grows the machine-rerun regression set from 11 → 12.

> **LLM reasoning break-ice experiment (not counted in KPI)**: With `scripts/_llm_breaking_ice.py --no-internal-presolve` (presolve shortcuts disabled, LLM forced to reason), `8/15` historical problems were solved by `main_agent_llm` autonomous reasoning on baidu Qianfan ERNIE (crypto×6 / reverse×1 / web×1; all sha256-verified — disk truth `deliverables/benchmark_runs/llm_breaking_ice_20260828-022534.json`; an earlier `10/15` count included two reverse solves whose sha256 did not match and was corrected). This proves real LLM reasoning capability exists, but it is **not** counted in `offline_verified` — that KPI only admits strict sha256-verified solves, and the 12 it holds are presolve-deterministic. Details in `MEMORY.md`.

Interpretation: **capability = static-analyzer coverage**, not LLM reasoning. To solve more problem types, write more deterministic skills. We say this plainly because over-claiming is the easiest way to embarrass an open-source security tool.

## Security & compliance

This repo publishes the **engineering skeleton and methodology only**. Red lines:

1. **Flags are handled per-event, honestly.** The large majority of historical-contest flags are stored as SHA-256. A small number of entries from long-public events (e.g. Anxun Cup 2020, whose write-ups are already public) retain plaintext flags. **Flags and attachments for the 2026 West Lake Sword contest itself are NOT included in this repo** (excluded via `.gitignore`). Truth files for the strict KPI live in `.gitignore`.
2. **No secrets in the repo.** LLM keys and platform tokens are injected via env vars / registry only.
3. **Internal contest resources are excluded** (`data/race_details/`, attachments, signatures) via `.gitignore`.
4. **Honest water-level.** We do not exaggerate capability. See above.

## License

[MIT](LICENSE) — open for learning and research. Respect each CTF's rules and platform terms.
