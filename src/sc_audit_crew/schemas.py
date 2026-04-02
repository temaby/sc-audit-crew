"""
Shared Pydantic schemas — single data format across all agents.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


# ------------------------------------------------------------------
# Enums
# ------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


class FindingCategory(str, Enum):
    # Security
    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    INTEGER_OVERFLOW = "integer_overflow"
    ORACLE_MANIPULATION = "oracle_manipulation"
    MEV_FRONTRUNNING = "mev_frontrunning"
    DELEGATECALL = "delegatecall"
    PROXY_STORAGE = "proxy_storage_collision"
    FLASH_LOAN = "flash_loan"
    LOGIC_ERROR = "logic_error"
    DOS = "denial_of_service"
    # Quality
    CODE_QUALITY = "code_quality"
    MISSING_NATSPEC = "missing_natspec"
    PATTERN_VIOLATION = "pattern_violation"
    # Architecture
    CENTRALIZATION = "centralization_risk"
    UPGRADE_RISK = "upgrade_risk"
    DEPENDENCY_RISK = "dependency_risk"


class FindingSource(str, Enum):
    STATIC_ANALYSIS = "static_analysis"
    MANUAL_REVIEW = "manual_review"
    THREAT_MODEL = "threat_model"
    CODE_QUALITY = "code_quality"


class VectorStatus(str, Enum):
    CHECKED = "checked"              # reviewed, no findings
    FLAGGED = "flagged"              # reviewed, findings generated
    NOT_APPLICABLE = "not_applicable"  # vector does not apply to this contract type


class VectorCoverage(BaseModel):
    """Coverage record for one security vector in the manual security audit."""
    vector_id: str = Field(..., description="Canonical ID: V01 through V19")
    vector: str = Field(..., description="Short human-readable vector label")
    status: VectorStatus
    summary: str = Field(
        ...,
        description="One sentence: what was checked, OR why not applicable",
    )
    finding_ids: List[str] = Field(
        default_factory=list,
        description="IDs of findings generated for this vector (e.g. MAN-003)",
    )


# ------------------------------------------------------------------
# Core Finding
# ------------------------------------------------------------------

class CodeLocation(BaseModel):
    file: str
    line_start: int
    line_end: Optional[int] = None
    function: Optional[str] = None

    def __str__(self) -> str:
        loc = f"{self.file}:{self.line_start}"
        if self.line_end:
            loc += f"-{self.line_end}"
        if self.function:
            loc += f" ({self.function})"
        return loc


class Finding(BaseModel):
    """
    Unified finding format shared across all agents.
    Peer Reviewer normalizes and deduplicates the list of Findings.
    """
    id: str = Field(..., description="Sequential ID: F-001, F-002, ...")
    source: FindingSource
    title: str
    severity: Severity
    category: FindingCategory
    location: CodeLocation
    description: str = Field(..., description="Detailed description of the vulnerability or issue")
    impact: str = Field(..., description="What can happen if not fixed")
    recommendation: str = Field(..., description="Concrete remediation steps")
    references: List[str] = Field(default_factory=list, description="SWC-ID, EIP, known exploits")
    poc_test: Optional[str] = Field(None, description="Foundry test code (Phase 2)")
    duplicate_of: Optional[str] = Field(None, description="ID of the primary finding if this is a duplicate")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Agent confidence 0.0-1.0")
    needs_poc: bool = Field(False, description="Flagged by peer_reviewer for PoC writing (Phase 2)")


# ------------------------------------------------------------------
# Audit Context — passed to all agents via crew inputs
# ------------------------------------------------------------------

class ContractFile(BaseModel):
    filename: str
    source_code: str
    compiler_version: str = "^0.8.0"


class AuditContext(BaseModel):
    """Input data for the full crew run."""
    project_name: str
    contracts: List[ContractFile]
    specification: Optional[str] = Field(None, description="Documentation / whitepaper")
    known_risks: Optional[str] = Field(None, description="Risks disclosed by the team")
    test_code: Optional[str] = Field(None, description="Test files source code (.sol / .ts / .js)")
    documentation: Optional[str] = Field(None, description="Additional documentation (.md files)")
    protocol_type: Optional[str] = Field(None, description="DEX / Lending / NFT / Bridge / ...")
    chain: str = "Ethereum mainnet"
    project_root: Optional[str] = None  # path to hardhat/foundry project on disk


# ------------------------------------------------------------------
# Aggregated audit result
# ------------------------------------------------------------------

class AuditReport(BaseModel):
    project_name: str
    audit_date: str
    findings: List[Finding]
    executive_summary: str
    scope: List[str]          # list of audited files
    methodology: str
    total_by_severity: dict   # {"Critical": 1, "High": 2, ...}

    def findings_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]
