"""
Smart Contract Audit Crew — EVM-focused, sequential process.

Pipeline:
    1. Code Quality Reviewer   — style, patterns, NatSpec
    2. Static Analysis Agent   — Slither (tool required)
    3. Security Auditor        — manual vulnerability review (vector files via VectorReadTool)
    4. Threat Modeler          — architecture, centralization, dependencies
    5. Peer Reviewer           — semantic dedup, false-positive filtering
    6. Severity Calibrator     — severity gates, needs_poc, final ordered list
    7. Report Writer           — final Markdown report
"""

import json
import os
import re
import textwrap
from pathlib import Path

from crewai import Agent, Crew, LLM, Process, Task
from crewai.project import CrewBase, agent, crew, task

from .tools import SlitherTool, EtherscanTool, VectorReadTool


# Filenames written after each task completes (in execution order)
TASK_FILES = [
    "01_code_quality.md",
    "02_static_analysis.md",
    "03_security_audit.md",
    "04_threat_modeling.md",
    "05_dedup.md",
    "06_severity_calibration.md",
    "audit_report.md",
]


def _extract_json(text: str) -> dict | list | None:
    """Extract JSON from raw text, a fenced code block, or embedded brace/bracket scan.

    Tries in order:
    1. Direct parse of the full text.
    2. Content of the first ```json...``` or ```...``` fenced block.
    3. Brace-scan: slice from the first '{' or '[' to the matching last '}' or ']'.
    """
    stripped = text.strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    # Fenced code block
    match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # Brace / bracket scan — handles JSON preceded or followed by prose
    for open_ch, close_ch in (("{" , "}"), ("[", "]")):
        start = text.find(open_ch)
        if start == -1:
            continue
        # Try the slice from first opening delimiter to last closing delimiter
        end = text.rfind(close_ch)
        if end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass

    return None


def _findings_for_fixer(calibration_data: dict) -> list[dict]:
    """
    Flatten severity_calibration_task output into a minimal list for a fixing agent.
    Fields: id, severity, title, file, line_start, line_end, function,
            description, recommendation, needs_fix.
    """
    findings = calibration_data.get("calibrated_findings", [])
    result = []
    for f in findings:
        if f.get("duplicate_of"):
            continue
        loc = f.get("location", {})
        if not isinstance(loc, dict):
            loc = {}
        result.append({
            "id": f.get("id"),
            "severity": f.get("severity"),
            "title": f.get("title"),
            "file": loc.get("file"),
            "line_start": loc.get("line_start"),
            "line_end": loc.get("line_end"),
            "function": loc.get("function"),
            "description": f.get("description"),
            "recommendation": f.get("recommendation"),
            "needs_fix": f.get("severity") in ("Critical", "High", "Medium"),
        })
    return result


class _SaveCallback:
    """Module-level serializable callback that writes task output to a file."""

    def __init__(self, output_dir: Path, filename: str) -> None:
        self.output_dir = output_dir
        self.filename = filename

    def __call__(self, task_output) -> None:
        path = self.output_dir / self.filename
        path.write_text(task_output.raw, encoding="utf-8")
        print(f"  >> Saved: {path}")


# ------------------------------------------------------------------
# Debug helpers
# ------------------------------------------------------------------

def _make_step_callback():
    """Return a step_callback for Crew() that prints tool calls and brief results.

    Only active when VERBOSE env var is set; otherwise returns None so CrewAI
    skips the callback entirely.
    """
    if os.getenv("VERBOSE", "0").lower() not in ("1", "true", "yes"):
        return None

    def _step(step) -> None:
        # CrewAI passes different objects depending on version:
        # AgentAction (tool call) or AgentFinish (final answer).
        try:
            tool = getattr(step, "tool", None)
            tool_input = getattr(step, "tool_input", None)
            output = getattr(step, "result", None) or getattr(step, "output", None)
            if tool:
                snippet = ""
                if output:
                    txt = str(output)
                    snippet = " → " + textwrap.shorten(txt, width=120, placeholder="...")
                print(f"  [step] TOOL={tool} input={textwrap.shorten(str(tool_input or ''), 80)}{snippet}")
            else:
                # Final answer or thought
                text = getattr(step, "text", None) or str(step)
                print(f"  [step] {textwrap.shorten(text, width=160, placeholder='...')}")
        except Exception:
            pass  # never crash the pipeline on a debug hook

    return _step


# All 19 canonical vector IDs expected in the security audit coverage matrix.
_EXPECTED_VECTORS = {
    "V01", "V02", "V03", "V04", "V05", "V06", "V07",
    "V08", "V09", "V10", "V11", "V12", "V13", "V14",
    "V15", "V16", "V17", "V18", "V19",
}


# ------------------------------------------------------------------
# Guardrail callables
# ------------------------------------------------------------------

_VALID_VECTOR_STATUSES = {"checked", "flagged", "not_applicable", "tool_error"}


def _make_security_audit_guardrail():
    """Return a per-task-run stateful guardrail for security_audit_task.

    Accumulates coverage entries across supplement retries so that each response
    only needs to contribute its missing portion.  When all 19 vectors are
    accounted for the guardrail reconstructs a fully merged JSON object and
    overwrites output.raw before returning success.
    """
    # Mutable state shared across successive calls within one task execution.
    _accumulated: dict[str, dict] = {}   # vid -> validated coverage entry
    _base: list[dict] = []               # single-element list: {contract_pragma}
    _findings_by_id: dict[str, dict] = {}  # finding_id -> finding object (merged across all rounds)

    def _guardrail(output) -> tuple[bool, str]:
        data = _extract_json(output.raw)
        if not isinstance(data, dict):
            return (False, "Output is not a valid JSON object. Re-emit the full JSON response with all 19 vectors.")

        # Determine coverage source: full response or incremental supplement.
        coverage = data.get("coverage")
        is_supplement = False
        if not isinstance(coverage, list):
            supplement = data.get("coverage_supplement")
            if isinstance(supplement, list):
                coverage = supplement
                is_supplement = True
            else:
                return (False, "Missing or invalid 'coverage' list. Re-emit the complete JSON object with all 19 vectors.")

        # On the first full (non-supplement) response, capture contract_pragma.
        if not is_supplement and not _base:
            _base.append({
                "contract_pragma": data.get("contract_pragma", "unknown"),
            })

        # Merge findings from every response (full and supplement) so that
        # findings introduced during supplement rounds are not lost.
        for f in (data.get("findings") or []):
            if isinstance(f, dict):
                fid = f.get("id")
                if fid and fid not in _findings_by_id:
                    _findings_by_id[fid] = f

        # Validate and accumulate coverage entries.
        bad_entries = []
        for entry in coverage:
            if not isinstance(entry, dict):
                bad_entries.append(str(entry))
                continue
            vid = entry.get("vector_id")
            status = entry.get("status")
            summary = entry.get("summary")
            finding_ids = entry.get("finding_ids")
            missing_fields = [
                f for f, v in [
                    ("vector_id", vid),
                    ("status", status),
                    ("summary", summary),
                    ("finding_ids", finding_ids),
                ]
                if not v and v != []
            ]
            if missing_fields:
                bad_entries.append(f"{vid or '?'}: missing fields {missing_fields}")
            elif status not in _VALID_VECTOR_STATUSES:
                bad_entries.append(f"{vid}: invalid status '{status}' (must be checked|flagged|not_applicable|tool_error)")
            else:
                _accumulated[vid] = entry

        missing_ids = sorted(_EXPECTED_VECTORS - set(_accumulated))

        errors = []
        if missing_ids:
            errors.append(f"Coverage incomplete: missing vectors {missing_ids}.")
        if bad_entries:
            errors.append(f"Malformed entries: {bad_entries}.")

        # Validate finding titles — check all newly received findings.
        bad_titles = []
        for f in (data.get("findings") or []):
            if isinstance(f, dict) and not f.get("title"):
                bad_titles.append(f.get("id", "?"))
        if bad_titles:
            errors.append(
                f"Findings with empty/missing title: {bad_titles}. "
                "Every finding must have a non-empty 'title' field."
            )

        if errors:
            filled_count = len(_accumulated)
            print(f"  [guardrail] retry: {filled_count}/19 vectors accumulated "
                  f"({sorted(_accumulated)} present, missing={missing_ids})")
            missing_only = missing_ids and not bad_entries and not bad_titles
            if missing_only:
                retry_msg = (
                    f"Coverage incomplete: the following {len(missing_ids)} vectors are absent from your output: "
                    f"{missing_ids}. "
                    "Emit ALL of those missing coverage entries in a SINGLE response — do not split across multiple replies. "
                    "Also include any NEW findings discovered while covering those vectors. "
                    'Schema: {"coverage_supplement": [...same coverage schema...], '
                    '"findings": [...any new Finding objects, empty array if none]}. '
                    "Do not re-emit vectors or findings already present. "
                    "coverage_supplement entries: vector_id, status, summary ≤15 words, finding_ids."
                )
            else:
                retry_msg = (
                    " ".join(errors)
                    + " Re-emit all 19 vectors (V01\u2013V19) with required fields"
                    + " vector_id, status (checked|flagged|not_applicable|tool_error), summary (\u226415 words), finding_ids."
                )
            return (False, retry_msg)

        # All 19 vectors accumulated.  Reconstruct a merged JSON object so that
        # the callback receives a coherent full output regardless of how many
        # supplement rounds were needed.
        print(f"  [guardrail] PASS: all 19 vectors present")
        base = _base[0] if _base else {"contract_pragma": "unknown"}
        merged = {
            "contract_pragma": base["contract_pragma"],
            "coverage": sorted(_accumulated.values(), key=lambda e: e.get("vector_id", "")),
            "findings": sorted(_findings_by_id.values(), key=lambda f: f.get("id", "")),
        }
        output.raw = json.dumps(merged, ensure_ascii=False)
        return (True, output)

    return _guardrail


def _guardrail_dedup(output) -> tuple[bool, str]:
    """Assert dedup_task output has required top-level structure.

    On success:
    - Fix A: overwrites output.raw with clean JSON (strips scratchpad prose)
             so calibration receives ~3-5K of structured data instead of
             500+ lines of scratchpad.
    - Fix B: strips `impact` from every deduplicated finding before the
             handoff — calibration gates never read it.  The calibration
             guardrail re-attaches impact from saved upstream task files.
    """
    data = _extract_json(output.raw)
    if not isinstance(data, dict):
        return (False, "Output is not a valid JSON object. Re-emit the complete JSON response.")

    errors = []

    if not isinstance(data.get("deduplicated_findings"), list):
        errors.append("'deduplicated_findings' must be a list.")

    stats_partial = data.get("stats_partial")
    if not isinstance(stats_partial, dict):
        errors.append("'stats_partial' must be an object.")
    else:
        required = {"total_before", "informational_dedup_confirmed"}
        missing = sorted(required - stats_partial.keys())
        if missing:
            errors.append(f"'stats_partial' is missing required keys: {missing}.")
        elif not stats_partial.get("informational_dedup_confirmed"):
            errors.append(
                "'stats_partial.informational_dedup_confirmed' must be true. "
                "Complete the POST-MERGE INFORMATIONAL CHECK before emitting output."
            )

    if not data.get("contract_pragma"):
        errors.append("'contract_pragma' must be present (use 'unknown' if not determinable).")

    if errors:
        return (
            False,
            " ".join(errors) + " Re-emit the complete JSON object with all required fields.",
        )

    # Fix B: strip `impact` — not used by any calibration gate.
    # The calibration guardrail re-attaches it from upstream task files.
    for f in (data.get("deduplicated_findings") or []):
        if isinstance(f, dict):
            f.pop("impact", None)

    n = len(data.get("deduplicated_findings") or [])
    print(f"  [guardrail/dedup] PASS: {n} findings; scratchpad stripped, impact deferred")

    # Fix A: overwrite with clean JSON — drops surrounding scratchpad prose.
    output.raw = json.dumps(data, ensure_ascii=False)
    return (True, output)


# Upstream task output files that carry the original `impact` strings.
# Listed in reverse-priority order: later entries win on ID collision.
_IMPACT_SOURCE_FILES = [
    "04_threat_modeling.md",
    "02_static_analysis.md",
    "01_code_quality.md",
    "03_security_audit.md",
]


def _build_impact_map(output_dir: Path) -> dict[str, str]:
    """Build {finding_id -> impact} from the four saved upstream task files.

    Called by the calibration guardrail to re-attach impact strings that were
    stripped from the dedup→calibration handoff (Fix B).
    """
    impact_map: dict[str, str] = {}
    for filename in _IMPACT_SOURCE_FILES:
        path = output_dir / filename
        if not path.exists():
            continue
        raw = path.read_text(encoding="utf-8")
        data = _extract_json(raw)
        if data is None:
            continue
        # Code quality: plain JSON array
        # Others: {"findings": [...]} or {"tool_status":{}, "findings":[]}
        findings = data if isinstance(data, list) else (data.get("findings") or [])
        for f in findings:
            if isinstance(f, dict):
                fid = f.get("id")
                impact = f.get("impact")
                if fid and impact:
                    impact_map[fid] = impact
    return impact_map


def _make_severity_calibration_guardrail(output_dir: Path | None):
    """Return a guardrail for severity_calibration_task.

    On success:
    - Re-attaches `impact` to each calibrated finding from the upstream task
      files saved on disk (undoes Fix B stripping in _guardrail_dedup).
    - Overwrites output.raw with clean JSON (strips calibration scratchpad
      prose so the report_writing_task context is compact).
    """
    def _guardrail(output) -> tuple[bool, str]:
        data = _extract_json(output.raw)
        if not isinstance(data, dict):
            return (False, "Output is not a valid JSON object. Re-emit the complete JSON response.")

        errors = []

        if not isinstance(data.get("calibrated_findings"), list):
            errors.append("'calibrated_findings' must be a list.")

        stats = data.get("stats")
        if not isinstance(stats, dict):
            errors.append("'stats' must be an object.")
        else:
            required = {"by_severity", "informational_dedup_confirmed"}
            missing = sorted(required - stats.keys())
            if missing:
                errors.append(f"'stats' is missing required keys: {missing}.")

        if errors:
            return (
                False,
                " ".join(errors) + " Re-emit the complete JSON object with all required fields.",
            )

        # Fix B: re-attach impact from upstream task files.
        calibrated = data.get("calibrated_findings") or []
        if output_dir is not None and calibrated:
            impact_map = _build_impact_map(output_dir)
            reattached = 0
            for f in calibrated:
                if isinstance(f, dict) and f.get("id") and not f.get("impact"):
                    impact = impact_map.get(f["id"])
                    if impact:
                        f["impact"] = impact
                        reattached += 1
            if reattached:
                print(f"  [guardrail/calibration] re-attached impact for {reattached} findings")

        n = len(calibrated)
        print(f"  [guardrail/calibration] PASS: {n} calibrated findings; scratchpad stripped")

        # Fix A: overwrite with clean JSON — drops surrounding scratchpad prose.
        output.raw = json.dumps(data, ensure_ascii=False)
        return (True, output)

    return _guardrail


class _SecurityAuditCallback:
    """Callback for security_audit_task: saves .md and prints a coverage matrix summary."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir

    def __call__(self, task_output) -> None:
        path = self.output_dir / "03_security_audit.md"
        path.write_text(task_output.raw, encoding="utf-8")
        print(f"  >> Saved: {path}")

        data = _extract_json(task_output.raw)
        if not isinstance(data, dict):
            print("  >> Coverage matrix: (could not parse JSON — skipping coverage check)")
            return

        coverage = data.get("coverage", [])
        covered_count = sum(1 for e in coverage if e.get("vector_id"))

        _sym = {"checked": "✓", "flagged": "!", "not_applicable": "—", "tool_error": "✗"}
        print(f"  >> Coverage matrix: {covered_count}/{len(_EXPECTED_VECTORS)} vectors")
        for entry in sorted(coverage, key=lambda e: e.get("vector_id", "")):
            vid = entry.get("vector_id", "?")
            status = entry.get("status", "?")
            sym = _sym.get(status, "?")
            label = entry.get("vector", "")
            print(f"       {sym} {vid} {label}")


class _DedupCallback:
    """Callback for dedup_task: saves deduplicated findings to disk."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir

    def __call__(self, task_output) -> None:
        data = _extract_json(task_output.raw)
        path = self.output_dir / "05_dedup.md"
        if data:
            path.write_text(
                "```json\n" + json.dumps(data, indent=2, ensure_ascii=False) + "\n```",
                encoding="utf-8",
            )
        else:
            path.write_text(task_output.raw, encoding="utf-8")
        print(f"  >> Saved: {path}")

        if data:
            gaps = (data.get("stats_partial") or {}).get("coverage_gaps", [])
            if gaps:
                print(f"  >> Coverage gaps: {gaps}")
            n = len(data.get("deduplicated_findings") or [])
            print(f"  >> Deduplicated findings: {n}")


class _CalibrationCallback:
    """Callback for severity_calibration_task: saves calibrated findings + findings.json."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir

    def __call__(self, task_output) -> None:
        data = _extract_json(task_output.raw)
        path = self.output_dir / "06_severity_calibration.md"
        if data:
            path.write_text(
                "```json\n" + json.dumps(data, indent=2, ensure_ascii=False) + "\n```",
                encoding="utf-8",
            )
        else:
            path.write_text(task_output.raw, encoding="utf-8")
        print(f"  >> Saved: {path}")

        if data:
            findings = _findings_for_fixer(data)
            findings_path = self.output_dir / "findings.json"
            findings_path.write_text(
                json.dumps(findings, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            print(f"  >> Saved: findings.json ({len(findings)} findings)")


@CrewBase
class SmartContractAuditCrew:
    """CrewAI team for EVM smart contract security auditing."""

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    def __init__(self, output_dir: Path | None = None, fast_mode: bool = False):
        self.output_dir = output_dir
        self.fast_mode = fast_mode
        self._verbose = os.getenv("VERBOSE", "0").lower() in ("1", "true", "yes")

    # ------------------------------------------------------------------
    # LLM helpers
    # ------------------------------------------------------------------

    def _llm(self, temperature: float = 0.1) -> LLM:
        """Fast model — static_analysis_agent only (tool calls + JSON parsing)."""
        return LLM(
            model=os.getenv("LLM_FAST", "gemini/gemini-2.5-flash-lite-preview"),
            temperature=temperature,
            max_tokens=16384,
        )

    def _llm_pro(self, temperature: float = 0.1) -> LLM:
        """Pro model for complex reasoning tasks (vulnerability analysis, dedup, report).

        In fast_mode, returns LLM_FAST for all agents to reduce cost and wall-clock time.
        """
        model = (
            os.getenv("LLM_FAST", "gemini/gemini-2.5-flash-lite-preview")
            if self.fast_mode
            else os.getenv("LLM_PRO", "gemini/gemini-2.5-flash-preview-04-17")
        )
        return LLM(
            model=model,
            temperature=temperature,
            max_tokens=16384 if self.fast_mode else 65536,
        )

    # ------------------------------------------------------------------
    # Agents
    # ------------------------------------------------------------------

    def _agent_kwargs(self) -> dict:
        """Extra kwargs applied to every agent (fast_mode lowers max_iter)."""
        return {"max_iter": 2} if self.fast_mode else {}

    @agent
    def code_quality_reviewer(self) -> Agent:
        return Agent(
            config=self.agents_config["code_quality_reviewer"],
            llm=self._llm_pro(temperature=0.1),
            verbose=self._verbose,
            **self._agent_kwargs(),
        )

    @agent
    def static_analysis_agent(self) -> Agent:
        return Agent(
            config=self.agents_config["static_analysis_agent"],
            llm=self._llm(temperature=0.0),
            tools=[],  # raw Slither output is pre-computed and injected via task description
            verbose=self._verbose,
            **self._agent_kwargs(),
        )

    @agent
    def security_auditor(self) -> Agent:
        # Python pre-filter (build_inputs) eliminates ~6 vectors before kickoff, leaving
        # ~13 applicable vectors.  Budget: 13 × (2 tool-call + 4 analysis) = 78 iterations.
        # 85 gives headroom without triggering supplement rounds on well-behaved models.
        extra = self._agent_kwargs()
        extra.setdefault("max_iter", 85)
        return Agent(
            config=self.agents_config["security_auditor"],
            llm=self._llm_pro(temperature=0.1),
            tools=[VectorReadTool()],
            verbose=self._verbose,
            **extra,
        )

    @agent
    def threat_modeler(self) -> Agent:
        return Agent(
            config=self.agents_config["threat_modeler"],
            llm=self._llm_pro(temperature=0.2),
            tools=[EtherscanTool()],
            verbose=self._verbose,
            **self._agent_kwargs(),
        )

    @agent
    def peer_reviewer(self) -> Agent:
        return Agent(
            config=self.agents_config["peer_reviewer"],
            llm=self._llm_pro(temperature=0.0),
            verbose=self._verbose,
            **self._agent_kwargs(),
        )

    @agent
    def severity_calibrator(self) -> Agent:
        return Agent(
            config=self.agents_config["severity_calibrator"],
            llm=self._llm_pro(temperature=0.0),
            verbose=self._verbose,
            **self._agent_kwargs(),
        )

    @agent
    def report_writer(self) -> Agent:
        return Agent(
            config=self.agents_config["report_writer"],
            llm=self._llm_pro(temperature=0.3),
            verbose=self._verbose,
            **self._agent_kwargs(),
        )

    # ------------------------------------------------------------------
    # Tasks
    # ------------------------------------------------------------------

    def _cb(self, filename: str):
        return _SaveCallback(self.output_dir, filename) if self.output_dir else None

    @task
    def code_quality_review_task(self) -> Task:
        return Task(
            config=self.tasks_config["code_quality_review_task"],
            callback=self._cb("01_code_quality.md"),
            async_execution=True,
        )

    @task
    def static_analysis_task(self) -> Task:
        return Task(
            config=self.tasks_config["static_analysis_task"],
            callback=self._cb("02_static_analysis.md"),
            async_execution=True,
        )

    @task
    def security_audit_task(self) -> Task:
        # Retries set to 3: the first output is often valid JSON but the agent needs
        # one or two attempts to produce well-formed output after a long tool-call chain.
        return Task(
            config=self.tasks_config["security_audit_task"],
            callback=_SecurityAuditCallback(self.output_dir) if self.output_dir else None,
            async_execution=True,
            guardrails=[_make_security_audit_guardrail()],
            guardrail_max_retries=22,
        )

    @task
    def threat_modeling_task(self) -> Task:
        return Task(
            config=self.tasks_config["threat_modeling_task"],
            callback=self._cb("04_threat_modeling.md"),
            async_execution=True,
        )

    @task
    def dedup_task(self) -> Task:
        # max_retries=3: dedup consolidates 4 upstream outputs with complex scratchpad phases;
        # a single malformed response gets two recovery attempts before propagating downstream.
        return Task(
            config=self.tasks_config["dedup_task"],
            callback=_DedupCallback(self.output_dir) if self.output_dir else None,
            guardrails=[_guardrail_dedup],
            guardrail_max_retries=3,
        )

    @task
    def severity_calibration_task(self) -> Task:
        # max_retries=3: calibration applies 8 gates; one retry was too fragile.
        # Factory receives output_dir so the guardrail can re-attach impact strings.
        return Task(
            config=self.tasks_config["severity_calibration_task"],
            callback=_CalibrationCallback(self.output_dir) if self.output_dir else None,
            guardrails=[_make_severity_calibration_guardrail(self.output_dir)],
            guardrail_max_retries=3,
        )

    @task
    def report_writing_task(self) -> Task:
        return Task(
            config=self.tasks_config["report_writing_task"],
            callback=self._cb("audit_report.md"),
        )

    # ------------------------------------------------------------------
    # Crew
    # ------------------------------------------------------------------

    @crew
    def crew(self) -> Crew:
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=self._verbose,
            step_callback=_make_step_callback(),
            max_retries=2
        )

    # ------------------------------------------------------------------
    # Single-step re-run helpers
    # ------------------------------------------------------------------

    def run_static_analysis_only(self, project_root: str, contract_names: list[str] | None = None) -> None:
        """Re-run only the static_analysis_task for a given target (project root or flat file).

        Runs SlitherTool directly (no LLM delegation) to avoid path-truncation
        hallucinations when the project directory name is long.
        """
        import json as _json
        from .tools import SlitherTool

        tool = SlitherTool()
        raw = tool._run(
            target=project_root,
            contract_names=list(contract_names or []),
            original_file_dir="",
        )

        try:
            data = _json.loads(raw)
        except Exception:
            data = {"error": raw}

        if "findings_count" in data:
            output = _json.dumps(
                {"tool_status": {"slither": "success"}, "findings": data.get("findings", [])},
                indent=2,
            )
        elif data.get("error") == "Slither is not installed":
            output = _json.dumps({"tool_status": {"slither": "not_installed"}, "findings": []})
        else:
            output = _json.dumps({
                "tool_status": {"slither": "error"},
                "findings": [],
                "hint": data.get("hint") or data.get("error", ""),
            })

        if self.output_dir:
            path = self.output_dir / "02_static_analysis_raw.md"
            path.write_text(output, encoding="utf-8")
            print(f"  >> Saved: {path}")

    def run_report_only(self, calibration_content: str, project_name: str,
                        audit_date: str, audit_scope: str) -> None:
        """Re-run only the report_writing_task using an existing calibration file.

        Bypasses the context mechanism: the calibration content is embedded
        directly into the task description so no prior tasks need to run.
        """
        cfg = self.tasks_config["report_writing_task"]

        description = (
            cfg["description"]
            .replace(
                "Use findings from severity_calibration_task.\n    "
                "The canonical finding list is in `calibrated_findings` "
                "(not `deduplicated_findings`).",
                "",
            )
            .format(
                project_name=project_name,
                audit_date=audit_date,
                audit_scope=audit_scope,
            )
            + f"\n\nSeverity calibration findings (from existing run):\n\n{calibration_content}"
        )

        task = Task(
            description=description,
            expected_output=cfg["expected_output"],
            agent=self.report_writer(),
            callback=self._cb("audit_report.md"),
        )

        Crew(
            agents=[self.report_writer()],
            tasks=[task],
            process=Process.sequential,
            verbose=self._verbose,
        ).kickoff()
