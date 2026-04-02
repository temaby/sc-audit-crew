"""
Smart Contract Audit Crew — EVM-focused, sequential process.

Pipeline:
    1. Code Quality Reviewer   — style, patterns, NatSpec
    2. Static Analysis Agent   — Slither (tool required)
    3. Security Auditor        — manual vulnerability review
    4. Threat Modeler          — architecture, centralization, dependencies
    5. Peer Reviewer           — dedup, normalize severity, flag needs_poc
    6. Report Writer           — final Markdown + JSON report
"""

import json
import os
import re
from pathlib import Path

from crewai import Agent, Crew, LLM, Process, Task
from crewai.project import CrewBase, agent, crew, task

from .tools import SlitherTool, EtherscanTool


# Filenames written after each task completes (in execution order)
TASK_FILES = [
    "01_code_quality.md",
    "02_static_analysis.md",
    "03_security_audit.md",
    "04_threat_modeling.md",
    "05_peer_review.md",
    "audit_report.md",
]


def _extract_json(text: str) -> dict | list | None:
    """Try to extract JSON from raw text or a ```json ... ``` code block."""
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        pass
    match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            pass
    return None


def _findings_for_fixer(peer_review_data: dict) -> list[dict]:
    """
    Flatten peer_review output into a minimal list optimized for a fixing agent.
    Fields: id, severity, title, file, line_start, line_end, function,
            description, recommendation, needs_fix.
    """
    findings = peer_review_data.get("deduplicated_findings", [])
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


# All 19 canonical vector IDs expected in the security audit coverage matrix.
_EXPECTED_VECTORS = {
    "V01", "V02", "V03", "V04", "V05", "V06", "V07",
    "V08", "V09", "V10", "V11", "V12", "V13", "V14",
    "V15", "V16", "V17", "V18", "V19",
}


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
        covered = {entry.get("vector_id") for entry in coverage if entry.get("vector_id")}
        missing = _EXPECTED_VECTORS - covered

        # Status symbol per entry
        _sym = {"checked": "✓", "flagged": "!", "not_applicable": "—"}
        total = len(_EXPECTED_VECTORS)
        covered_count = len(covered)

        print(f"  >> Coverage matrix: {covered_count}/{total} vectors")
        for entry in sorted(coverage, key=lambda e: e.get("vector_id", "")):
            vid = entry.get("vector_id", "?")
            status = entry.get("status", "?")
            sym = _sym.get(status, "?")
            label = entry.get("vector", "")
            print(f"       {sym} {vid} {label}")
        if missing:
            for vid in sorted(missing):
                print(f"       ✗ {vid} MISSING from coverage")
            print(f"  >> WARNING: {len(missing)} vector(s) not covered: {sorted(missing)}")


class _PeerReviewCallback:
    """Module-level serializable callback for peer review: saves .md + findings.json."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir

    def __call__(self, task_output) -> None:
        (self.output_dir / "05_peer_review.md").write_text(task_output.raw, encoding="utf-8")
        print(f"  >> Saved: 05_peer_review.md")

        data = _extract_json(task_output.raw)
        if data:
            # Report coverage gaps surfaced by peer reviewer
            gaps = data.get("stats", {}).get("coverage_gaps", [])
            if gaps:
                print(f"  >> Coverage gaps confirmed by peer reviewer: {gaps}")

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
            tools=[SlitherTool()],
            verbose=self._verbose,
            **self._agent_kwargs(),
        )

    @agent
    def security_auditor(self) -> Agent:
        return Agent(
            config=self.agents_config["security_auditor"],
            llm=self._llm_pro(temperature=0.1),
            verbose=self._verbose,
            **self._agent_kwargs(),
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
        return Task(
            config=self.tasks_config["security_audit_task"],
            callback=_SecurityAuditCallback(self.output_dir) if self.output_dir else None,
            async_execution=True,
        )

    @task
    def threat_modeling_task(self) -> Task:
        return Task(
            config=self.tasks_config["threat_modeling_task"],
            callback=self._cb("04_threat_modeling.md"),
            async_execution=True,
        )

    @task
    def peer_review_task(self) -> Task:
        return Task(
            config=self.tasks_config["peer_review_task"],
            callback=_PeerReviewCallback(self.output_dir) if self.output_dir else None,
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
            #tasks=[self.code_quality_review_task()],
            tasks=self.tasks,
            process=Process.sequential,
            verbose=self._verbose,
            max_retries=2
        )

    # ------------------------------------------------------------------
    # Single-step re-run helpers
    # ------------------------------------------------------------------

    def run_static_analysis_only(self, project_root: str, contract_names: list[str] | None = None) -> None:
        """Re-run only the static_analysis_task for a given target (project root or flat file)."""
        task = Task(
            config=self.tasks_config["static_analysis_task"],
            agent=self.static_analysis_agent(),
            callback=self._cb("02_static_analysis.md"),
        )
        Crew(
            agents=[self.static_analysis_agent()],
            tasks=[task],
            process=Process.sequential,
            verbose=self._verbose,
        ).kickoff(inputs={
            "slither_target": project_root,
            "contract_names": contract_names or [],
        })

    def run_report_only(self, peer_review_content: str, project_name: str,
                        audit_date: str, audit_scope: str) -> None:
        """Re-run only the report_writing_task using an existing peer review file.

        Bypasses the context mechanism: the peer review content is embedded
        directly into the task description so no prior tasks need to run.
        """
        cfg = self.tasks_config["report_writing_task"]

        description = (
            cfg["description"]
            .replace("Use findings from peer_review_task.", "")
            .format(
                project_name=project_name,
                audit_date=audit_date,
                audit_scope=audit_scope,
            )
            + f"\n\nPeer review findings (from existing run):\n\n{peer_review_content}"
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
