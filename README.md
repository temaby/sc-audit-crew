# SCAuditCrew

> AI-powered smart contract security audit crew built on [CrewAI](https://crewai.com).

A multi-agent pipeline that performs automated security audits of EVM smart contracts. Each agent has a specialized role — from static analysis to threat modeling — producing a structured audit report and a machine-readable findings file.

---

## How It Works

```
contracts + tests + docs
         │
         ▼
┌────────┴────────────────────────────────────────────┐
│  PARALLEL (async_execution=True)                    │
│                                                     │
│  ┌──────────────────┐  ┌──────────────────────────┐ │
│  │  Code Quality    │  │  Static Analysis Agent   │ │
│  │  Reviewer        │  │  Slither, false-positive  │ │
│  │  NatSpec, CEI,   │  │  filtered, confidence    │ │
│  │  gas, visibility │  │  mapped to 0.0–1.0       │ │
│  └──────────────────┘  └──────────────────────────┘ │
│                                                     │
│  ┌──────────────────┐  ┌──────────────────────────┐ │
│  │  Security        │  │  Threat Modeler          │ │
│  │  Auditor         │  │  architecture risks,     │ │
│  │  19-vector EVM   │  │  centralization, L2,     │ │
│  │  manual review   │  │  Etherscan verify        │ │
│  └──────────────────┘  └──────────────────────────┘ │
└────────────────────────┬────────────────────────────┘
                         │ (all four complete)
                         ▼
              ┌──────────────────────┐
              │  Peer Reviewer       │  semantic dedup, severity
              │  (sequential)        │  normalization, Critical Gate,
              └──────────┬───────────┘  math verification, PoC flags
                         │
              ┌──────────▼───────────┐
              │  Report Writer       │  Markdown report with deployment
              │  (sequential)        │  verdict, conditional PoC sections
              └──────────────────────┘
```

Each agent writes its output file immediately upon completion via callbacks — no waiting for the full pipeline. If the run fails mid-way, all files produced up to that point are preserved.

---

## Output

```
output/
└── MyProject_2026-03-25/
    ├── 01_code_quality.md       # Code quality findings
    ├── 02_static_analysis.md    # Slither results
    ├── 03_security_audit.md     # Manual security review (19-vector coverage matrix)
    ├── 04_threat_modeling.md    # Architecture & threat model
    ├── 05_peer_review.md        # Deduplicated & normalized findings (JSON)
    ├── findings.json            # Machine-readable findings
    └── audit_report.md          # Final human-readable report with deployment verdict
```

`findings.json` is a flat array optimized for downstream automated pipelines:

```json
[
  {
    "id": "MAN-001",
    "source": "manual_review",
    "severity": "High",
    "title": "Intermediate type truncation in _baseVestedAmount",
    "location": {
      "file": "Vault.sol",
      "line_start": 147,
      "function": "_baseVestedAmount"
    },
    "description": "...",
    "recommendation": "...",
    "needs_poc": true
  }
]
```

Finding IDs preserve their source prefix throughout the pipeline (`QA-`, `SA-`, `MAN-`, `TM-`, `PR-`) and are never renumbered. The `needs_poc` boolean is set by the peer reviewer: `true` for Critical and High findings. The report writer renders a **Proof of Concept** section only for those findings.

The Executive Summary in `audit_report.md` always ends with a deployment verdict:

```
**Deployment Verdict: NOT RECOMMENDED FOR DEPLOYMENT** — Critical findings present.
**Deployment Verdict: CONDITIONAL — FIXES REQUIRED** — High/Medium findings present.
**Deployment Verdict: LOW RISK** — only Low/Informational findings, or no findings.
```

HTML reports are published automatically to GitHub Pages via GitHub Actions on every push to `master` that touches the `output/` directory.

---

## Installation

**Requirements:** Python 3.11+

```bash
git clone https://github.com/your-username/SCAuditCrew
cd SCAuditCrew
python -m venv .venv
source .venv/Scripts/activate  # Windows
# source .venv/bin/activate    # Linux / macOS
pip install -e .
```

Copy and fill in your API keys:

```bash
cp .env.example .env
```

```env
# LLM provider keys — set the one matching your chosen models
GOOGLE_API_KEY=your_google_ai_studio_key
# ANTHROPIC_API_KEY=your_anthropic_key
# OPENAI_API_KEY=your_openai_key

ETHERSCAN_API_KEY=your_etherscan_key   # optional, for on-chain analysis
```

**Optional — Slither for static analysis:**

```bash
pip install slither-analyzer
solc-select install 0.8.20 && solc-select use 0.8.20
```

---

## Usage

**Audit a single contract:**

```bash
sc-audit --contract ./src/Vault.sol --name "Vault"
```

**Audit a Foundry / Hardhat project** (auto-discovers tests and docs):

```bash
sc-audit --project ./my_protocol --name "MyProtocol" --protocol-type "Lending"
```

**With explicit paths:**

```bash
sc-audit --project ./my_protocol \
         --name "MyProtocol" \
         --spec ./docs/spec.md \
         --tests ./test \
         --docs ./docs \
         --chain "Arbitrum"
```

**All options:**

| Flag              | Description                                             | Default            |
| ----------------- | ------------------------------------------------------- | ------------------ |
| `--project`       | Path to foundry/hardhat project                         | —                  |
| `--contract`      | Path to a single `.sol` file                            | —                  |
| `--name`          | Project name (required)                                 | —                  |
| `--spec`          | Path to specification file                              | —                  |
| `--tests`         | Path to tests dir/file (auto-discovered if `--project`) | —                  |
| `--docs`          | Path to docs dir/file (auto-discovered if `--project`)  | —                  |
| `--protocol-type` | DEX / Lending / NFT / Bridge / ...                      | `DeFi`             |
| `--chain`         | Target chain                                            | `Ethereum mainnet` |
| `--output`        | Base output directory                                   | `./output`         |

---

## Models

Two model slots are configured in `.env`:

```env
LLM_FAST=gemini/gemini-2.5-flash-lite   # static_analysis_agent (tool calls + JSON)
LLM_PRO=gemini/gemini-2.5-flash         # all other agents (reasoning + writing)
```

| Agent                 | Slot       | Default model           |
| --------------------- | ---------- | ----------------------- |
| Code Quality Reviewer | `LLM_PRO`  | `gemini-2.5-flash`      |
| Static Analysis Agent | `LLM_FAST` | `gemini-2.5-flash-lite` |
| Security Auditor      | `LLM_PRO`  | `gemini-2.5-flash`      |
| Threat Modeler        | `LLM_PRO`  | `gemini-2.5-flash`      |
| Peer Reviewer         | `LLM_PRO`  | `gemini-2.5-flash`      |
| Report Writer         | `LLM_PRO`  | `gemini-2.5-flash`      |

Any [litellm-supported model](https://docs.litellm.ai/docs/providers) works. For best audit quality set `LLM_PRO`:

```env
LLM_PRO=anthropic/claude-sonnet-4-6
```

Based on testing on real contracts, Claude Sonnet 4.6 produces significantly fewer false positives, correctly applies severity gates, and consolidates duplicate findings — compared to Gemini Flash.

---

---

## Prompt Engineering

The agents use hardcoded quality gates and decision rules to reduce noise and improve consistency.

### Security Audit — 19-Vector Coverage Matrix

The security auditor reasons through all 19 vectors on every run and emits a coverage entry for each (`checked` / `flagged` / `not_applicable`). Omitting a vector is not allowed. Protocol-specific gates short-circuit irrelevant checks:

- **V10** (vesting termination invariant) — only applied when `{protocol_type}` is `vesting`, `streaming`, or `lockup`; otherwise `not_applicable`.
- **V17** (initializer security) — only applied when the contract skeleton shows a proxy pattern; otherwise `not_applicable`.

### Deduplication — Two-Pass in Semantic-First Order

1. **PRIMARY PASS — Semantic dedup**: scan all findings for pairs sharing the same root cause and overlapping location, regardless of title. Merge into the higher-severity entry.
2. **SECONDARY PASS — Title collapse**: group remaining findings by title (case-insensitive); collapse groups > 1 into one entry listing all locations.

After both passes, no two remaining findings may share both an overlapping location range and the same root cause.

### Critical Severity Gate

Before the peer reviewer emits `severity=Critical`, all three must be true:

1. Direct fund-loss path exists (concrete, not hypothetical).
2. No special preconditions (e.g. not "only if owner is malicious").
3. Exploit flow fits in one sentence.

Fails any → downgrade to High or Medium.

**Centralization downgrade rule**: if the only exploit path requires a malicious insider (owner, admin), the maximum severity is Medium.

### Type Truncation Severity (V07)

Intermediate arithmetic on sub-256-bit types (e.g. `uint112 * uint40`) overflows at the operand type even under Solidity ≥0.8 checked arithmetic, permanently reverting the calling function. Default severity is **High**. The peer reviewer may upgrade to **Critical** if the bricked function is the primary withdrawal/claim path and the revert is unconditional.

### Self-Verification Step (Security Auditor)

Before finalizing each finding, the auditor must re-read the cited lines. Inline arithmetic must be shown. CEI-correct code (all guard-state writes before the external call) must not be flagged as a reentrancy violation. Events after external calls are not CEI violations.

### Slither False-Positive Filtering

The static analysis agent recognizes and suppresses five common Slither false-positive patterns:

| Slither detector                 | False-positive condition                                       |
| -------------------------------- | -------------------------------------------------------------- |
| `arbitrary-send-eth`             | Internal/private function, only callable from controlled path  |
| `reentrancy-*`                   | Fired on `view`/`pure` function                                |
| `calls-loop`                     | In `view`/`pure` with no state change → downgrade to Info      |
| `divide-before-multiply`         | Intentional interval truncation (e.g. `(t/interval)*interval`) |
| `tautology` / `boolean-equality` | Macro-generated constant expression                            |

### SA Confidence Semantics

Slither findings carry a confidence field (mapped: `high=0.9`, `medium=0.6`, `low=0.3`). This reflects **detector trigger reliability**, not exploitability. Unlike `manual_review` findings (where `confidence < 0.3` triggers a severity downgrade), SA confidence values are informational only.

### Mathematical Claim Rule

Any finding with a quantitative claim ("net is zero", "fees total 100%") must include an inline step-by-step calculation. If the calculation disproves the claim, the finding is removed.

### Tool Fallbacks

- **Slither unavailable**: returns `{"tool_status": {"slither": "not_installed"}, "findings": []}`. Pipeline continues.
- **EtherscanTool unavailable**: sets `etherscan_status: "not_available"` and proceeds without on-chain verification. No fabrication.

### Report Style Rules

The report writer follows concrete style rules: third person throughout, quantified impact (user class, % funds, conditions), imperative mood for recommendations, and qualified language (`may`, `could`) for unconfirmed findings.

---

## Project Structure

```
src/sc_audit_crew/
├── crew.py              # Agent and task definitions (@CrewBase)
├── main.py              # CLI entry point
├── schemas.py           # Pydantic models (Finding, AuditContext, ...)
├── tools.py             # Slither, Etherscan tools
├── generate_pages.py    # HTML report generator for GitHub Pages
└── config/
    ├── agents.yaml      # Agent roles, goals, backstories
    └── tasks.yaml       # Task descriptions and expected outputs
```

---

---

## Roadmap

**Phase 1 — MVP ✅**

- Sequential 6-agent pipeline with first 4 tasks running in parallel (`async_execution=True`)
- Slither integration with false-positive filtering
- Auto-discovery of tests and documentation
- Per-task output files written on completion via callbacks
- `findings.json` — flat structured output with source-prefixed IDs (QA-, SA-, MAN-, TM-)
- 19-vector coverage matrix with `not_applicable` gates for V10 and V17
- Two-pass semantic-first deduplication
- Critical Severity Gate, Centralization Downgrade Rule
- Type-truncation severity model (V07 High / peer-upgrade-to-Critical)
- Deployment verdict in Executive Summary
- Conditional PoC sections (`needs_poc` per finding)
- Tool fallbacks for Slither and EtherscanTool
- GitHub Actions + GitHub Pages for HTML report publishing

**Phase 2 — Quality & Scale (next)**

- Pydantic-validated structured output from each agent
- PoC writer with Foundry test generation
- Context chunking for large multi-file projects
- Symbolic execution integration for formal bytecode analysis

**Phase 3 — Production**

- Invariant & property testing (Echidna / Halmos)
- Multi-run diffing (what changed since last audit)
- Caching and incremental re-runs

---

## Related Work

| Tool                                                | Approach                     | Open source |
| --------------------------------------------------- | ---------------------------- | ----------- |
| [Slither](https://github.com/crytic/slither)        | Static analysis (rule-based) | ✓           |
| [Mythril](https://github.com/Consensys/mythril)     | Symbolic execution           | ✓           |
| [GPTScan](https://github.com/MetaTrustLabs/GPTScan) | Single LLM, pattern matching | ✓           |
| [Audit Wizard](https://auditwizard.io)              | Single AI agent, commercial  | ✗           |
| [Certora](https://certora.com)                      | Formal verification + AI     | ✗           |

SCAuditCrew focuses on a **multi-agent collaborative pipeline** with specialized roles, prompt-level quality gates, and integration of established static analysis tools.

---

## License

MIT
