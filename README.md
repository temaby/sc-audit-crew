# SCAuditCrew

> AI-powered smart contract security audit crew built on [CrewAI](https://crewai.com).

A multi-agent pipeline that performs automated security audits of EVM smart contracts. Each agent has a specialized role — from static analysis to threat modeling — producing a structured audit report and a machine-readable findings file.

---

## How It Works

```
contracts + tests + docs
         │
         ▼
┌─────────────────────┐
│  Code Quality       │  NatSpec, CEI pattern, gas inefficiencies,
│  Reviewer           │  magic numbers, function length, visibility
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│  Static Analysis    │  Slither (subprocess call, real tool output)
│  Agent              │
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│  Security Auditor   │  manual EVM vulnerability review:
│                     │  reentrancy, access control, oracle manip,
│                     │  MEV, flash loans, decimal scaling, DoS...
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│  Threat Modeler     │  centralization, upgradeability, economic
│                     │  security, L2 risks, Etherscan verification
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│  Peer Reviewer      │  dedup, severity normalization, Critical Gate,
│                     │  math verification, findings consolidation
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│  Report Writer      │  professional Markdown audit report
└─────────────────────┘
```

Each agent writes its output file immediately upon completion via callbacks — no waiting for the full pipeline. If the run fails mid-way, all files produced up to that point are preserved.

---

## Output

```
output/
└── MyProject_2026-03-25/
    ├── 01_code_quality.md       # Code quality findings
    ├── 02_static_analysis.md    # Slither results
    ├── 03_security_audit.md     # Manual security review
    ├── 04_threat_modeling.md    # Architecture & threat model
    ├── 05_peer_review.md        # Deduplicated & normalized findings (JSON)
    ├── findings.json            # Machine-readable findings
    └── audit_report.md          # Final human-readable report
```

`findings.json` is a flat array optimized for downstream automated pipelines:

```json
[
  {
    "id": "F-001",
    "severity": "High",
    "title": "Reentrancy in withdraw()",
    "file": "src/Vault.sol",
    "line_start": 42,
    "function": "withdraw",
    "description": "...",
    "recommendation": "...",
    "needs_poc": true
  }
]
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

## Prompt Engineering

The agents use several hardcoded quality gates to reduce noise:

**Critical Severity Gate** — before emitting `severity=Critical`, the peer reviewer must confirm: (1) direct fund-loss path exists, (2) no special preconditions, (3) exploit fits in one sentence. Fails any → downgrade to High/Medium.

**Self-Verification Step** (Security Auditor) — mandatory re-read of cited lines before finalizing each finding. Arithmetic must be shown inline. CEI-correct code (state before external call) must not be flagged.

**Consolidation Rule** — findings with identical or near-identical titles are merged into one entry listing all affected locations. Applies especially to NatSpec, magic numbers, visibility issues.

**Mathematical Claim Rule** — any quantitative claim ("net is zero", "fees total 100%") must include the step-by-step calculation. If the calculation disproves the claim, the finding is removed.

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

## Roadmap

**Phase 1 — MVP ✅**

- Sequential 6-agent pipeline
- Slither integration with false-positive filtering
- Auto-discovery of tests and documentation
- Per-task output files written on completion via callbacks
- `findings.json` — flat structured output
- Critical Severity Gate, Mathematical Claim Rule, Self-Verification Step
- GitHub Actions + GitHub Pages for HTML report publishing

**Phase 2 — Quality & Scale (next)**

- Parallel execution of the first 4 agents (`async_execution`)
- Pydantic-validated structured output from each agent
- PoC writer with Foundry test generation
- Context chunking for large multi-file projects
- Symbolic execution via [Mythril](https://github.com/Consensys/mythril) for formal bytecode analysis

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
