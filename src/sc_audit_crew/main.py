"""
Entry point for SmartContractAuditCrew.

Usage:
    sc-audit --project ./my_protocol --name "MyProtocol"
    sc-audit --contract ./Token.sol --name "SimpleToken"
    sc-audit --project ./my_protocol --name "MyProtocol" --tests ./test --docs ./docs
"""

from __future__ import annotations

import argparse
import os
import re
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from .crew import SmartContractAuditCrew
from .schemas import AuditContext, ContractFile


# ------------------------------------------------------------------
# Loaders
# ------------------------------------------------------------------

def make_output_dir(base: str, project_name: str) -> Path:
    """Create and return output/{safe_name}_{date}/ directory."""
    safe_name = re.sub(r"[^\w\-]", "_", project_name)
    date_str = datetime.now().strftime("%Y-%m-%d")
    output_dir = Path(base) / f"{safe_name}_{date_str}"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def load_contracts_from_dir(project_root: str) -> list[ContractFile]:
    """Load all .sol files from src/ or contracts/ directory (tests and flat files excluded)."""
    root = Path(project_root)
    contracts = []

    def _is_flat(path: Path) -> bool:
        return any(path.match(pat) for pat in _FLAT_PATTERNS)

    for d in ["src", "contracts", "."]:
        sol_dir = root / d
        if sol_dir.exists():
            for sol_file in sorted(sol_dir.rglob("*.sol")):
                if any(p in sol_file.parts for p in ["test", "Test", "mock", "Mock"]):
                    continue
                if _is_flat(sol_file):
                    continue
                contracts.append(ContractFile(
                    filename=str(sol_file.relative_to(root)),
                    source_code=sol_file.read_text(),
                ))
            if contracts:
                break

    return contracts


_SKIP_DIRS = {"node_modules", "artifacts", "cache", "out", ".git", "lib"}
_TEST_DIRS = {"test", "tests", "spec"}
_DOCS_DIRS = {"docs", "doc", "documentation"}
_FLAT_DIRS = {"flat", "flattened", "flatten"}
_TEST_PATTERNS = ("*.t.sol", "*.test.sol", "*.ts", "*.js")
_DOCS_PATTERNS = ("*.md",)
_FLAT_PATTERNS = ("*.flat.sol", "*_flat.sol", "*flattened*.sol")


def _collect_files(root: Path, patterns: tuple[str, ...]) -> list[Path]:
    """Recursively collect files matching patterns, skipping known junk dirs."""
    files = []
    for pattern in patterns:
        for f in sorted(root.rglob(pattern)):
            if any(x in f.parts for x in _SKIP_DIRS):
                continue
            files.append(f)
    return files


def _format_files(files: list[Path], root: Path) -> str:
    parts = []
    for f in files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        parts.append(f"=== {f.relative_to(root)} ===\n{content}")
    return "\n\n".join(parts)


def load_tests(path: str) -> str:
    """Load test files from an explicit path (file or directory)."""
    p = Path(path)
    if not p.exists():
        return ""
    if p.is_file():
        return f"=== {p.name} ===\n{p.read_text(encoding='utf-8', errors='ignore')}"
    return _format_files(_collect_files(p, _TEST_PATTERNS), p)


def load_docs(path: str) -> str:
    """Load documentation files from an explicit path (file or directory)."""
    p = Path(path)
    if not p.exists():
        return ""
    if p.is_file():
        return f"=== {p.name} ===\n{p.read_text(encoding='utf-8', errors='ignore')}"
    return _format_files(_collect_files(p, _DOCS_PATTERNS), p)


def autodiscover_tests(project_root: str) -> str:
    """Auto-discover test files inside a project directory."""
    root = Path(project_root)
    files = []
    for d in _TEST_DIRS:
        test_dir = root / d
        if test_dir.exists():
            files.extend(_collect_files(test_dir, _TEST_PATTERNS))
    return _format_files(files, root)


def autodiscover_flat(project_root: str) -> Path | None:
    """Auto-discover a flat .sol file inside a project directory.

    Search order:
    1. Known flat subdirectories (_FLAT_DIRS) for files matching _FLAT_PATTERNS
    2. Project root itself for files matching _FLAT_PATTERNS

    Returns the first match, or None if not found.
    """
    root = Path(project_root)

    for d in _FLAT_DIRS:
        flat_dir = root / d
        if flat_dir.exists():
            files = _collect_files(flat_dir, _FLAT_PATTERNS)
            if files:
                return files[0]

    files = _collect_files(root, _FLAT_PATTERNS)
    return files[0] if files else None


def autodiscover_docs(project_root: str) -> str:
    """Auto-discover documentation inside a project directory."""
    root = Path(project_root)
    files = []

    # Top-level README
    for f in sorted(root.glob("README*")):
        if f.is_file():
            files.append(f)

    # Known docs directories
    for d in _DOCS_DIRS:
        docs_dir = root / d
        if docs_dir.exists():
            files.extend(_collect_files(docs_dir, _DOCS_PATTERNS))

    return _format_files(files, root)


def _number_lines(source: str) -> str:
    """Prefix each line with its 1-based line number: '  42: code...'"""
    lines = source.splitlines()
    width = len(str(len(lines)))
    return "\n".join(f"{str(i + 1).rjust(width)}: {line}" for i, line in enumerate(lines))


_FN_BODY_START = re.compile(r"\b(function|modifier|constructor|fallback|receive)\b")


def _generate_skeleton(source: str) -> str:
    """Strip function/modifier/constructor/fallback/receive bodies from Solidity source.

    Keeps: pragma, imports, state variables, events, errors, struct/enum definitions,
    function signatures with NatSpec comments. Replaces every function body with { ... }.
    """
    lines = source.splitlines()
    result: list[str] = []
    depth = 0
    skipping_body = False
    pending_fn = False  # True after seeing a function-like keyword, waiting for opening {

    for raw_line in lines:
        opens = raw_line.count("{")
        closes = raw_line.count("}")
        new_depth = depth + opens - closes

        if skipping_body:
            if new_depth <= 1:
                skipping_body = False
                pending_fn = False
            depth = new_depth
            continue

        # Detect a function/modifier/constructor keyword at contract level
        if depth == 1 and _FN_BODY_START.search(raw_line):
            pending_fn = True

        if pending_fn and depth == 1 and opens > closes and new_depth >= 2:
            # This line opens the function body — emit signature up to { then { ... }
            brace_idx = raw_line.find("{")
            prefix = raw_line[:brace_idx].rstrip()
            result.append(prefix + " { ... }")
            skipping_body = True
            depth = new_depth
            continue

        result.append(raw_line)
        depth = new_depth

    return "\n".join(result)


# Context budget thresholds (approximate tokens: 1 token ≈ 4 chars for Solidity/English)
_CONTEXT_WARN_TOKENS = 60_000
_CONTEXT_ERROR_TOKENS = 120_000


def _estimate_tokens(text: str) -> int:
    """Rough token estimate sufficient for budget warnings (not billing-accurate)."""
    return len(text) // 4


def _validate_context_budget(full_source: str) -> None:
    """Print a warning when contracts_full_source is large enough to risk quality degradation."""
    tokens = _estimate_tokens(full_source)
    if tokens > _CONTEXT_ERROR_TOKENS:
        print(
            f"\n[WARNING] Contract source is ~{tokens:,} tokens "
            f"(>{_CONTEXT_ERROR_TOKENS // 1000}K). Quality degradation is likely.\n"
            f"  Consider: --flat (pre-flattened file) or splitting the audit scope.\n"
            f"  Skeleton representation sent to Threat Modeler is ~{tokens // 10:,} tokens.\n"
        )
    elif tokens > _CONTEXT_WARN_TOKENS:
        print(
            f"\n[INFO] Contract source is ~{tokens:,} tokens "
            f"(>{_CONTEXT_WARN_TOKENS // 1000}K). This is within range but approaching the limit.\n"
        )


# ------------------------------------------------------------------
# Protocol-type normalisation
# ------------------------------------------------------------------

_CANONICAL_PROTOCOL_TYPES = {
    "vesting", "streaming", "lockup",
    "AMM", "lending", "bridge", "governance", "staking", "vault", "generic",
}

# Priority order: most specific first.
_PROTOCOL_TYPE_KEYWORDS: dict[str, list[str]] = {
    "vesting":    ["vest", "cliff", "grant", "unlock", "drip", "entitlement", "salary", "payroll"],
    "streaming":  ["stream", "flow", "sablier"],
    "lockup":     ["lockup", "lock-up", "time-lock", "escrowed"],
    "AMM":        ["amm", "swap", "dex", "liquidity", "uniswap", "curve", "balancer"],
    "lending":    ["lend", "borrow", "collateral", "cdp", "debt", "credit", "aave", "compound"],
    "bridge":     ["bridge", "cross-chain", "crosschain", "relay", "wormhole"],
    "governance": ["governance", "voting", "dao", "proposal", "governor"],
    "staking":    ["stak", "validator", "delegation", "restake"],
    "vault":      ["vault", "erc4626", "4626", "yield", "strategy", "harvest", "yearn"],
}


def _normalize_protocol_type(raw: str) -> str:
    """Map free-text protocol descriptions to a canonical enum value.

    Canonical values: vesting | streaming | lockup | AMM | lending | bridge |
                      governance | staking | generic

    Logic:
    1. Exact match (case-insensitive) against canonical values.
    2. Keyword scan in priority order (first match wins).
    3. No match → "generic" + WARNING printed to stdout.
    """
    lower = raw.strip().lower()

    # 1. Exact match (case-insensitive)
    for canonical in _CANONICAL_PROTOCOL_TYPES:
        if lower == canonical.lower():
            return canonical

    # 2. Keyword scan
    for canonical, keywords in _PROTOCOL_TYPE_KEYWORDS.items():
        for kw in keywords:
            if kw in lower:
                return canonical

    # 3. Unrecognized
    options = " | ".join(sorted(_CANONICAL_PROTOCOL_TYPES))
    print(
        f"\n[WARNING] Unrecognized --protocol-type '{raw}'. "
        f"Falling back to 'generic'.\n"
        f"  Valid values: {options}\n"
    )
    return "generic"


def build_inputs(ctx: AuditContext, project_root: str, slither_target: str | None = None) -> dict:
    """Build inputs dict for crew.kickoff()."""
    contracts_full_source = "\n\n".join(
        f"=== {c.filename} ===\n{_number_lines(c.source_code)}"
        for c in ctx.contracts
    )
    contracts_skeleton = "\n\n".join(
        f"=== {c.filename} ===\n{_generate_skeleton(c.source_code)}"
        for c in ctx.contracts
    )
    audit_scope = "\n".join(
        f"- {c.filename} ({len(c.source_code.splitlines())} lines)"
        for c in ctx.contracts
    )

    _validate_context_budget(contracts_full_source)

    return {
        "project_name": ctx.project_name,
        "protocol_type": ctx.protocol_type or "Unknown",
        "chain": ctx.chain,
        "contracts_full_source": contracts_full_source,
        "contracts_skeleton": contracts_skeleton,
        "audit_scope": audit_scope,
        "main_contract_path": ctx.contracts[0].filename if ctx.contracts else "",
        "project_root": project_root,
        "slither_target": slither_target or project_root,
        "contract_names": [Path(c.filename).stem.split(".")[0] for c in ctx.contracts],
        "specification": ctx.specification or "No specification provided.",
        "known_risks": ctx.known_risks or "None specified.",
        "test_code": ctx.test_code or "No test files provided.",
        "documentation": ctx.documentation or "No documentation provided.",
        "deployed_address": "None",
        "audit_date": datetime.now().strftime("%Y-%m-%d"),
    }


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

# Per-million-token prices (input, output) for known model name substrings.
# Matched in order — first match wins.
_MODEL_PRICES: list[tuple[str, float, float]] = [
    ("claude-sonnet-4",       3.00,  15.00),
    ("claude-3-5-sonnet",     3.00,  15.00),
    ("claude-3-haiku",        0.25,   1.25),
    ("claude",                3.00,  15.00),
    ("gemini-2.5-flash-lite", 0.075,  0.30),
    ("gemini-2.5-flash",      0.15,   0.60),
    ("gemini-2.0-flash-lite", 0.075,  0.30),
    ("gemini-2.0-flash",      0.10,   0.40),
    ("gemini-flash",          0.10,   0.40),
    ("gemini",                0.15,   0.60),
    ("gpt-4o-mini",           0.15,   0.60),
    ("gpt-4o",                2.50,  10.00),
]


def _cost_for_model(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    model_lower = model.lower()
    for substr, price_in, price_out in _MODEL_PRICES:
        if substr in model_lower:
            return (prompt_tokens * price_in + completion_tokens * price_out) / 1_000_000
    # Unknown model — assume a mid-range price
    return (prompt_tokens * 1.00 + completion_tokens * 4.00) / 1_000_000


def _print_and_save_cost_summary(metrics, output_dir: Path, model_pro: str, model_fast: str) -> None:
    """Print a cost summary table and write cost_summary.txt to output_dir."""
    prompt_tokens = getattr(metrics, "prompt_tokens", 0) or 0
    completion_tokens = getattr(metrics, "completion_tokens", 0) or 0
    total_tokens = getattr(metrics, "total_tokens", 0) or (prompt_tokens + completion_tokens)

    # Use LLM_PRO pricing as the conservative estimate (most tokens go through it)
    est_cost = _cost_for_model(model_pro, prompt_tokens, completion_tokens)

    sep = "-" * 56
    lines = [
        "",
        "=" * 56,
        "  Audit Cost Summary",
        sep,
        f"  {'Metric':<28} {'Value':>24}",
        sep,
        f"  {'Prompt tokens':<28} {prompt_tokens:>24,}",
        f"  {'Completion tokens':<28} {completion_tokens:>24,}",
        f"  {'Total tokens':<28} {total_tokens:>24,}",
        sep,
        f"  {'Model (pro / 5 agents)':<28} {model_pro:>24}",
        f"  {'Model (fast / 1 agent)':<28} {model_fast:>24}",
        sep,
        f"  {'Estimated cost (USD)':<28} {'${:.4f}'.format(est_cost):>24}",
        "=" * 56,
        "  Note: cost estimate uses LLM_PRO pricing for all tokens.",
        "  Actual cost is slightly lower (static_analysis_agent uses LLM_FAST).",
        "",
    ]
    output = "\n".join(lines)
    print(output)

    summary_path = output_dir / "cost_summary.txt"
    summary_path.write_text(output.strip(), encoding="utf-8")
    print(f"  >> Saved: {summary_path}")


def _check_api_keys(args) -> None:
    """Verify that at least one LLM API key is set for the active models."""
    fast_mode = getattr(args, "fast_mode", False)
    models = {
        os.getenv("LLM_FAST", "gemini/gemini-2.5-flash-lite-preview"),
        os.getenv("LLM_PRO" if not fast_mode else "LLM_FAST",
                  "gemini/gemini-2.5-flash-lite-preview" if fast_mode
                  else "gemini/gemini-2.5-flash-preview-04-17"),
    }
    _KEY_MAP = [
        ("anthropic/", "ANTHROPIC_API_KEY"),
        ("openai/",    "OPENAI_API_KEY"),
        ("gemini/",    "GOOGLE_API_KEY"),
        ("google/",    "GOOGLE_API_KEY"),
    ]
    for model in models:
        for prefix, key_name in _KEY_MAP:
            if prefix in model.lower():
                if not os.getenv(key_name):
                    raise EnvironmentError(
                        f"{key_name} is not set (required for model '{model}')"
                    )
                break


def _find_latest_output_dir(base: str, project_name: str) -> Path | None:
    """Return the most recently modified output dir for the given project name."""
    safe_name = re.sub(r"[^\w\-]", "_", project_name)
    base_path = Path(base)
    candidates = sorted(
        base_path.glob(f"{safe_name}_*"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def run():
    parser = argparse.ArgumentParser(description="Smart Contract Audit Crew")
    parser.add_argument("--project", help="Path to a foundry/hardhat project directory")
    parser.add_argument("--contract", help="Path to a single .sol file")
    parser.add_argument("--name", required=True, help="Project name")
    parser.add_argument("--spec", help="Path to specification / documentation file")
    parser.add_argument("--tests", help="Path to tests directory or file (.sol / .ts / .js)")
    parser.add_argument("--docs", help="Path to documentation directory or file (.md)")
    parser.add_argument("--flat", help="Path to a pre-flattened .sol file for Slither (all imports inlined)")
    parser.add_argument(
        "--protocol-type", default="generic",
        help=(
            "Protocol category. Canonical values: "
            "vesting | streaming | lockup | AMM | lending | bridge | governance | staking | vault | generic. "
            "Free-text synonyms are accepted and normalized (e.g. 'yield-farming' → AMM, "
            "'cliff-vesting' → vesting). Unrecognized input falls back to 'generic'."
        ),
    )
    parser.add_argument("--chain", default="Ethereum mainnet",
                        help="Target chain (e.g. 'Arbitrum', 'Base', 'Polygon'). Affects L2-specific threat model checks.")
    parser.add_argument("--output", default="./output", help="Base output directory")
    parser.add_argument(
        "--only-step",
        choices=["static-analysis", "report"],
        help="Run a single step in isolation. "
             "'static-analysis' requires --project or --contract. "
             "'report' requires --resume-dir or auto-detects the latest output folder.",
    )
    parser.add_argument(
        "--resume-dir",
        help="Path to an existing output directory to resume from "
             "(used with --only-step report). Auto-detected if omitted.",
    )
    parser.add_argument(
        "--fast-mode",
        action="store_true",
        help="Use LLM_FAST for all agents (cheaper, quicker, lower quality). "
             "Intended for live demos. Not recommended for production audits.",
    )
    args = parser.parse_args()

    _check_api_keys(args)

    args.protocol_type = _normalize_protocol_type(args.protocol_type)

    # ------------------------------------------------------------------
    # Single-step re-run mode
    # ------------------------------------------------------------------
    if args.only_step == "static-analysis":
        if not args.project and not args.contract:
            raise ValueError("--only-step static-analysis requires --project or --contract")

        if args.project:
            project_root = args.project
        else:
            project_root = str(Path(args.contract).parent)

        if args.flat:
            flat_abs = Path(args.flat).resolve()
            if not flat_abs.exists():
                raise FileNotFoundError(f"--flat file not found: {flat_abs}")
            slither_target = str(flat_abs)
        else:
            flat_path = autodiscover_flat(project_root)
            slither_target = str(flat_path.resolve()) if flat_path else project_root

        output_dir = make_output_dir(args.output, args.name)

        print(f"\n{'='*60}")
        print(f"  Re-running step: static-analysis")
        print(f"  Slither target : {slither_target}")
        print(f"  Output dir     : {output_dir}")
        print(f"{'='*60}\n")

        # Derive contract names for filtering (best-effort)
        if args.project:
            _sa_contracts = load_contracts_from_dir(args.project)
        elif args.contract:
            _sa_contracts = [ContractFile(
                filename=Path(args.contract).name,
                source_code="",
            )]
        else:
            _sa_contracts = []
        _sa_contract_names = [Path(c.filename).stem.split(".")[0] for c in _sa_contracts]

        SmartContractAuditCrew(output_dir=output_dir).run_static_analysis_only(
            project_root=slither_target,
            contract_names=_sa_contract_names,
        )

        print(f"\n{'='*60}")
        print(f"  Result written to: {output_dir / '02_static_analysis.md'}")
        print(f"{'='*60}\n")
        return

    if args.only_step:
        output_dir = (
            Path(args.resume_dir)
            if args.resume_dir
            else _find_latest_output_dir(args.output, args.name)
        )
        if not output_dir or not output_dir.exists():
            raise ValueError(
                f"Output directory not found. Use --resume-dir to specify it explicitly."
            )

        if args.only_step == "report":
            peer_review_path = output_dir / "05_peer_review.md"
            if not peer_review_path.exists():
                raise FileNotFoundError(
                    f"05_peer_review.md not found in {output_dir}. "
                    "Run the full audit first or point --resume-dir at a valid output folder."
                )
            peer_review_content = peer_review_path.read_text(encoding="utf-8")

            # Reconstruct minimal scope from existing output files
            existing_files = sorted(output_dir.glob("*.md"))
            audit_scope = "\n".join(f"- {f.name}" for f in existing_files)

            print(f"\n{'='*60}")
            print(f"  Re-running step: report")
            print(f"  Output dir     : {output_dir}")
            print(f"  Peer review    : {peer_review_path.name} ({len(peer_review_content)} chars)")
            print(f"{'='*60}\n")

            SmartContractAuditCrew(output_dir=output_dir).run_report_only(
                peer_review_content=peer_review_content,
                project_name=args.name,
                audit_date=datetime.now().strftime("%Y-%m-%d"),
                audit_scope=audit_scope,
            )

            print(f"\n{'='*60}")
            print(f"  Report written to: {output_dir / 'audit_report.md'}")
            print(f"{'='*60}\n")
        return

    # Load contracts
    if args.resume_dir and not args.only_step:
        print("  [WARNING] --resume-dir has no effect without --only-step. Ignored.\n")

    if args.project:
        contracts = load_contracts_from_dir(args.project)
        project_root = args.project
    elif args.contract:
        sol_path = Path(args.contract)
        contracts = [ContractFile(
            filename=sol_path.name,
            source_code=sol_path.read_text(),
        )]
        project_root = str(sol_path.parent)
    else:
        raise ValueError("Specify --project or --contract")

    if not contracts:
        raise ValueError("No .sol files found")

    spec = Path(args.spec).read_text(encoding="utf-8") if args.spec else None

    if args.tests:
        test_code = load_tests(args.tests)
    elif args.project:
        test_code = autodiscover_tests(args.project)
    else:
        test_code = None

    if args.docs:
        documentation = load_docs(args.docs)
    elif args.project:
        documentation = autodiscover_docs(args.project)
    else:
        documentation = None

    if args.flat:
        flat_abs = Path(args.flat).resolve()
        if not flat_abs.exists():
            raise FileNotFoundError(f"--flat file not found: {flat_abs}")
        slither_target = str(flat_abs)
    else:
        flat_path = autodiscover_flat(project_root)
        slither_target = str(flat_path.resolve()) if flat_path else project_root

    output_dir = make_output_dir(args.output, args.name)

    if args.fast_mode:
        print(f"\n{'!'*60}")
        print(f"  [FAST MODE] Using LLM_FAST for all agents.")
        print(f"  Output quality is reduced. Not for production audits.")
        print(f"{'!'*60}\n")

    print(f"\n{'='*60}")
    print(f"  Smart Contract Audit: {args.name}")
    print(f"  Contracts    : {len(contracts)}")
    print(f"  Protocol     : {args.protocol_type} on {args.chain}")
    print(f"  Tests        : {'yes' if test_code else 'no'}")
    print(f"  Docs         : {'yes' if documentation else 'no'}")
    print(f"  Slither      : {slither_target}")
    print(f"  Output       : {output_dir}")
    print(f"{'='*60}\n")

    ctx = AuditContext(
        project_name=args.name,
        contracts=contracts,
        specification=spec,
        test_code=test_code,
        documentation=documentation,
        protocol_type=args.protocol_type,
        chain=args.chain,
        project_root=project_root,
    )

    inputs = build_inputs(ctx, project_root, slither_target=slither_target)

    audit_crew = SmartContractAuditCrew(output_dir=output_dir, fast_mode=args.fast_mode)
    crew_obj = audit_crew.crew()
    try:
        crew_obj.kickoff(inputs=inputs)
    except Exception as e:
        print(f"\n{'='*60}")
        print(f"  AUDIT FAILED: {type(e).__name__}: {e}")
        print(f"  Partial results saved to: {output_dir}")
        print(f"{'='*60}\n")
        raise

    print(f"\n{'='*60}")
    print(f"  Audit complete!")
    print(f"  Output folder: {output_dir}")
    print(f"{'='*60}\n")

    try:
        _print_and_save_cost_summary(
            crew_obj.usage_metrics,
            output_dir,
            model_pro=os.getenv("LLM_FAST" if args.fast_mode else "LLM_PRO",
                                "gemini/gemini-2.5-flash-lite-preview" if args.fast_mode
                                else "gemini/gemini-2.5-flash-preview-04-17"),
            model_fast=os.getenv("LLM_FAST", "gemini/gemini-2.5-flash-lite-preview"),
        )
    except Exception as exc:
        print(f"  [cost summary] could not compute: {exc}")


if __name__ == "__main__":
    run()
